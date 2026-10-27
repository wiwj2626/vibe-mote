# -*- coding: utf-8 -*-
"""语音通道：遥控器语音键 + 遥控器麦克风 → 虚拟声卡。

两条链路都在 ATVV 私有服务（ab5e0001）上，和普通按键走的 HID 完全不同：

    ab5e0002  控制特征（写）   —— 连上后发一次 GET_CAPS 让遥控器进录音态
    ab5e0003  音频特征（通知） —— 16kHz IMA ADPCM，128 字节一帧，无帧头
    ab5e0004  状态特征（通知） —— b[0]==0x04 按住语音键 / 0x00 松开

音频处理全部用纯 Python（不依赖 numpy）：128B ADPCM → 256 个 16k 样本 →
去直流 → 线性插值升到 48k → 增益 / AGC → 软限幅 → 虚拟声卡。
16k 解码 + 48k 输出一共才 6.4 万样本/秒，纯 Python 绰绰有余。

★ 铁律：遥控器的 BLE 通道同一时间只能有一个客户端。第二个客户端拿到的
  服务表只剩 4 个基础服务（1800/1801/180a/180f），ATVV 会整个消失 ——
  日志表现就是「缺少 ATVV 特征」。所以每次开新会话前必须先把上一条关干净。
"""
from __future__ import annotations

import asyncio
import ctypes
import math
import threading
import time

import i18n
import keys

ADDR_DEFAULT = ""

ATVV_CTL = "ab5e0002"
ATVV_AUDIO = "ab5e0003"
ATVV_STATUS = "ab5e0004"

# ★ 遥控器「醒着」的判定窗口：按下任意键之后，它大约还会醒这么久。
#   这是语音唯一值得尝试连接的时机 —— 睡得越久越连不上，等没有意义。
HID_AWAKE_WINDOW_S = 20.0

# ★ 按键之后**必须等这么久**再去建链。这条是 2026-10-27 用三张一样的坏表换来的。
#
#   按键的那一刻，Windows 的 HID 子设备正在和遥控器建立**加密**链路。谁先连上，
#   谁就决定了这条链的加密状态 —— 而遥控器只对已加密的链暴露 00001812(HID) 和
#   ab5e0001(ATVV)；未加密时只给 1800/1801/180a/180f/1813 这五个。
#
#   实测对照（同一支遥控器、同一台机器）：
#     · 13:16:09 按键 → 中间走了 3 秒连接超时 + 扫广播 + 重连，15 秒后才连上
#       → 服务表 10 个，含 ab5e0001，随后 8 段语音全部成功（93/98/70/140/112/74/60/61 帧）
#     · 13:18:42、13:22:34 按键 → 几乎紧接着就发起连接
#       → 三次都只拿到那 5 个基础服务，ATVV 整个消失
#
#   所以「立刻重试」在这里不是优点，是 bug。等它握稳再上。
HID_POST_KEY_SETTLE_S = 2.5

# 但也不能无限等：用户要是在连按方向键，活动时刻会一直被刷新。
HID_SETTLE_CAP_S = 6.0

# 只拿到基础服务（说明抢到了一条未加密的新链）之后，别原地立刻再来一次 ——
# 那会把刚让回去的 HID 又挤掉。退一下，让 Windows 重新握稳。
UNPAIRED_RETRY_DELAY_S = 8.0


# ─── ATVV 命令 ──────────────────────────────────────────────────────────
# ★ 这三条字节是 2026-10-27 从一个成熟实现（remotemic-src / RC003，
#   ovb_rc003/chromecast_voice.py 与 atvv_protocol.py）对着核出来的。
#
#   之前这里发的是 `0A 00 04 00 01`（5 字节），**是畸形报文**：ATVV v1.0 的
#   GET_CAPS 是 [0x0A][Version:2][Codecs:1][Interaction:1]，必须 6 字节。
#   遥控器收到畸形报文直接忽略 —— 也就是说：
#       「空闲 20 秒补发 GET_CAPS 保活」这一整条路径**从来没起过作用**。
#   日志里那行 `GET_CAPS 已写入` 只能证明"写操作没报错"，证明不了遥控器认。
#
#   v1.0 的形态（version >= 0x0100，本机实测遥控器就是 v1.0）：
#     GET_CAPS  = 0A 01 00 00 02 03      (Version=0x0100, Codecs=0x02 ADPCM,
#                                          Interaction=0x03 PTT|HTT)
#     MIC_OPEN  = 0C 00                  (2 字节)
#     MIC_CLOSE = 0D <session_id>        (2 字节，带回当前会话号)
#   v0.x 的形态（只有老固件才用，保留兜底）：
#     MIC_OPEN  = 0C 00 00 / MIC_CLOSE = 0D 00 00
# ★ 2026-10-27 16:23 真机实测：`0A 01 00 00 03 03` **能换来 CAPS 应答**
#   （协议 v1.0，编码 16kHz ADPCM，交互 0x03，帧长 240）；而 `0A 01 00 00 02 03`
#   （remotemic-src 的 chromecast_voice.py 用的那个变体）**没有应答**。
#   两者的差别在第 5 字节：0x03 vs 0x02（服务能力位）。
#   atvv_protocol.py 里用的正是 03 03 这个变体 —— 我们抄错了那份。
CAPS_CMD = bytes([0x0A, 0x01, 0x00, 0x00, 0x03, 0x03])
CAPS_CMD_ALT = bytes([0x0A, 0x01, 0x00, 0x00, 0x02, 0x03])  # 另一个变体（无应答，留作对照）
# ★ MIC_CLOSE 必须带**正确的会话号**（`0D <session_id>`，见 atvv_protocol.py 的
#   mic_close_command）。会话号在遥控器发的 `0x04` 帧里：`04 <reason> <codec> <sid>`。
#   我们以前永远发 `0D 00` —— 会话号对不上时关麦指令会被忽略，会话就挂着，
#   这很可能就是"按红外键之后语音永久失效"的机制。
#   这里留个 2 字节的构造函数，真正用的时候把会话号填进去。
MIC_OPEN_CMD = bytes([0x0C, 0x00])
MIC_CLOSE_CMD = bytes([0x0D, 0x00])          # 兜底（会话号未知时）
MIC_OPEN_CMD_V0 = bytes([0x0C, 0x00, 0x00])
MIC_CLOSE_CMD_V0 = bytes([0x0D, 0x00, 0x00])

# 控制通道（ab5e0004）的操作码。0x0B 是**遥控器回给我们的能力应答** ——
# 这是整条链路上唯一一个"你问它，它一定得答"的东西，所以它能当探活心跳用。
OP_AUDIO_STOP = 0x00
OP_AUDIO_START = 0x04
OP_MIC_BUTTON = 0x08
OP_AUDIO_SYNC = 0x0A
OP_CAPS = 0x0B

# 等 CAPS 应答的时限。超过就算这次协商失败（参考实现的 CAPABILITIES_TIMEOUT）。
CAPS_TIMEOUT_S = 3.0

# 连续几轮"问了不回"就判定 ATVV 僵死。取 2 轮，配合 20 秒的间隔 =
# 最多 40 秒就能发现，比原来的"永远发现不了"强。
CAPS_MISS_LIMIT = 2


def describe_services(client):
    """把服务表压成一行：`ab5e0001[ab5e0002:w,ab5e0003:n,ab5e0004:n] …`

    为什么要它：「连上了、就绪了、按语音键却没反应」这类问题，第一步必须确认
    `ab5e0002/3/4` 到底在不在、属性对不对 —— 没有这一行，只能靠猜。
    属性缩写：r=read w=write W=write-without-response n=notify i=indicate。
    """
    short = {"read": "r", "write": "w", "write-without-response": "W",
             "notify": "n", "indicate": "i", "broadcast": "b"}
    out = []
    try:
        for s in client.services:
            chars = []
            for c in s.characteristics:
                props = "".join(short.get(p, "?") for p in (c.properties or []))
                chars.append(f"{str(c.uuid).lower()[:8]}:{props}")
            out.append(f"{str(s.uuid).lower()[:8]}[{','.join(chars)}]")
    except Exception as e:
        return f"（枚举失败 {type(e).__name__}: {e}）"
    return " ".join(out) or "（空）"

SR_IN, SR_OUT = 16000, 48000


def probe_mic(seconds=1.0):
    """读一秒**系统默认输入设备**，报出峰值 —— 给"声音输入不进去"这类问题定性。

    为什么要它：用户报"不管电脑麦克风阵列还是遥控器，电平都是 0"时，第一件要分清的是
    **系统这边本来就没声音**（隐私设置/设备静音/驱动卡死/硬件静音键）还是**我们没读到**。
    这里用和普通应用完全一样的方式（WASAPI 默认输入端点）读一秒，把原始峰值写进日志 ——
    连 0 都是 0 的话，就是系统侧的事，跟本程序无关。

    ⚠ 不用 sd.rec / numpy：本项目刻意不依赖 numpy（声音处理是纯 Python），
    所以走 RawInputStream + int16 字节，峰值用标准库 array 算。
    """
    import sounddevice as sd
    from array import array
    try:
        dev = sd.default.device[0]
    except Exception:
        dev = None
    name = i18n.L("（没有默认输入设备）", "(no default input device)")
    try:
        if dev is not None and int(dev) >= 0:
            name = str(sd.query_devices(int(dev))["name"])
    except Exception:
        pass
    frames = max(1, int(16000 * seconds))
    try:
        with sd.RawInputStream(device=dev, samplerate=16000, channels=1,
                               dtype="int16", blocksize=1600) as st:
            raw = bytes(st.read(frames)[0])
        a = array("h")
        a.frombytes(raw[:len(raw) - (len(raw) % 2)])
        peak = max((abs(v) for v in a), default=0)
    except Exception as e:
        return i18n.L(f"麦克风自检失败：{type(e).__name__}: {e}",
                      f"Microphone self-check failed: {type(e).__name__}: {e}")
    lvl = 100.0 * peak / 32768.0
    if lvl < 0.5:
        verdict = i18n.L(
            "→ 读数几乎是 0，说明**系统这边就没有声音进来**（跟本程序无关）。按顺序查："
            "① 设置 → 隐私和安全性 → 麦克风（允许访问 + 允许桌面应用）；"
            "② 该设备的「级别」有没有被拉到 0 或被静音；"
            "③ 笔记本的**麦克风静音键/指示灯**（硬件静音会让所有输入都是 0）；"
            "④ 重启一次电脑（音频驱动卡死时只有重启能救）；"
            "⑤ 关掉可能独占麦克风的其他程序（会议/变声/OBS）。",
            "→ Essentially 0, which means **no audio is reaching Windows at all** (nothing to do "
            "with this program). Check in order: (1) Settings → Privacy & security → Microphone "
            "(allow access + allow desktop apps); (2) that device's Level slider / mute; (3) a laptop's "
            "microphone-mute key or LED (hardware mute zeroes every input); (4) reboot (a stuck audio "
            "driver only recovers on reboot); (5) close programs that may hold the mic exclusively "
            "(meetings / voice changers / OBS).")
    else:
        verdict = i18n.L("→ 电平正常（对着麦克风说话时应有明显读数）。",
                         "→ Level looks normal (talking into the mic should read clearly).")
    return i18n.L(
        f"麦克风自检：默认输入设备「{name}」，{seconds:.0f} 秒内峰值 {lvl:.1f}%"
        f"（原始 {peak}/32768）。{verdict}"
        + _cable_naming_hint(),
        f"Microphone self-check: default input “{name}”, peak over {seconds:.0f}s is {lvl:.1f}% "
        f"(raw {peak}/32768). {verdict}"
        + _cable_naming_hint(en=True))


def _dev_name(idx):
    """设备索引 → 名字（find_cable 返回的是索引；日志给用户看要用名字）。"""
    try:
        import sounddevice as sd
        return str(sd.query_devices(int(idx))["name"])
    except Exception:
        return ""


def _cable_naming_hint(en=False):
    """把 VB-CABLE 那对"反直觉"的名字说清楚 —— 每个用户都会问一次。"""
    try:
        cable_in, cable_out = find_cable()
    except Exception:
        cable_in = cable_out = None
    n_in = _dev_name(cable_in) or "CABLE Input"
    n_out = _dev_name(cable_out) or "CABLE Output"
    if not (cable_in is not None or cable_out is not None):
        return ""
    if en:
        return (f" Note: VB-CABLE names its ends from the cable's point of view — "
                f"「{n_in}」 shows up under **Playback** (programs write into it) "
                f"and 「{n_out}」 shows up under **Recording** (programs read from it). "
                f"So the IME must pick the Output end: this program writes into the Input end.")
    return (f" 注：VB-CABLE 的名字是「从线缆角度」起的 —— "
            f"「{n_in}」出现在**播放设备**里（程序往里写），"
            f"「{n_out}」出现在**录制设备**里（程序从它读）。"
            f"所以输入法要选的是 **Output** 那一个：本程序往 Input 那一端写。")


UNSTICK_COOLDOWN = 600.0        # 自动解卡最短间隔（秒）：别把用户蓝牙反复关开


async def unstick_bluetooth():
    """把蓝牙电台关开一次 —— 拆掉"被系统 HID 攥住"的那条唯一 BLE 连接。

    为什么用 Windows 的 Radio API（而不是 PnP）：
      ① 它跟「设置 → 蓝牙」那个开关是**同一个机制**，实测**不需要管理员**；
      ② PnP 那条路在真机上根本走不通（`Disable-PnpDevice` 对某些 Intel 电台直接报
         "不支持" HRESULT 0x8004100c，`pnputil /restart-device` 又要求重启系统）；
      ③ 它能**读回状态** —— 所以可以确认"确实开回来了"，绝不会把电台丢在关闭状态
         （这正是用户最怕的事："我的蓝牙设备全没了"）。

    返回 (结果, 说明)：restarted / turned-on / unavailable / failed
    """
    try:
        from winrt.windows.devices.radios import Radio, RadioKind, RadioState
    except Exception as e:
        return "unavailable", i18n.L(f"没有 Radio API（{e!r}）",
                                     f"the Radio API is unavailable ({e!r})")
    radio = None
    try:
        for r in await Radio.get_radios_async():
            if r.kind == RadioKind.BLUETOOTH:
                radio = r
                break
    except Exception as e:
        return "unavailable", i18n.L(f"读蓝牙电台失败：{type(e).__name__}: {e}",
                                     f"could not read the Bluetooth radio: "
                                     f"{type(e).__name__}: {e}")
    if radio is None:
        return "unavailable", i18n.L("系统里没有蓝牙电台", "no Bluetooth radio on this system")
    if radio.state != RadioState.ON:
        # 本来就关着：只打开，不再去关它（少一个动作少一份风险）
        for _ in range(3):
            try:
                await radio.set_state_async(RadioState.ON)
            except Exception:
                pass
            await asyncio.sleep(1.5)
            if radio.state == RadioState.ON:
                return "turned-on", i18n.L("电台原本是关的，已打开", "it was off; turned it on")
        return "failed", i18n.L(f"打不开蓝牙（当前状态 {radio.state}）",
                                f"could not turn Bluetooth on (state {radio.state})")
    try:
        await radio.set_state_async(RadioState.OFF)
    except Exception as e:
        return "failed", i18n.L(f"关闭蓝牙失败：{type(e).__name__}: {e}",
                                f"could not turn Bluetooth off: {type(e).__name__}: {e}")
    await asyncio.sleep(3.0)
    for attempt in range(1, 4):
        try:
            await radio.set_state_async(RadioState.ON)
        except Exception:
            pass
        await asyncio.sleep(2.0)
        if radio.state == RadioState.ON:
            return "restarted", i18n.L(f"第 {attempt} 次确认已开回",
                                       f"confirmed back on (attempt {attempt})")
    return "failed", i18n.L(f"关开之后没能开回来（当前状态 {radio.state}）—— "
                            f"请立刻到「设置 → 蓝牙」手动打开",
                            f"it did not come back on (state {radio.state}) — "
                            f"turn Bluetooth back on in Settings right away")


def pairing_hint(name, text):
    """把蓝牙那几句"天书"翻译成该干什么。

    真机见过两次（别人机器上）：
      · `BleakGATTProtocolError: (5, 'GATT Protocol Error: Insufficient Authentication')`
        —— 遥控器的 ATT 服务要求一条**已加密**的链路，而 Windows 这边没拿那对密钥，
        **几乎都是配对没配好**：最有效的是"删掉设备重新配对"，不是重启程序、更不是动驱动。
      · 连接直接被拒/找不到设备 —— 系统里根本没配好这台设备。
    返回空串表示"这句我认不出来，不瞎猜"。
    """
    t = f"{name} {text}".lower()
    if "insufficient authentication" in t or "insufficient_authentication" in t:
        return i18n.L(
            "语音：遥控器要求一条已加密的链路（GATT Insufficient Authentication）—— "
            "通常是配对没配好。请到「设置 → 蓝牙和其他设备」把遥控器**删除设备**，"
            "然后按住遥控器的【返回 + 主页】重新配对，回来再点「重启」。"
            "（不用动驱动、不用重装程序）",
            "Voice: the remote requires an encrypted link (GATT Insufficient Authentication) — "
            "this is almost always an incomplete pairing. Remove the device under "
            "Settings → Bluetooth & devices, then hold 【Back + Home】 on the remote to pair it "
            "again, and click Restart afterwards. (No drivers, no reinstall.)")
    if "not paired" in t or "unreachable" in t or "not found" in t or "device not found" in t:
        return i18n.L(
            "语音：系统里找不到这台设备 —— 先在「设置 → 蓝牙和其他设备」把它配上，再点「重启」。",
            "Voice: the device was not found in Windows — pair it under "
            "Settings → Bluetooth & devices first, then click Restart.")
    return ""
FRAME_BYTES = 128
# 高通截止频率：人声主体在 300–3400 Hz，男声基频最低 ~85 Hz，
# 所以 100 Hz 既安全又够用（ASR 前端一般 80–100 Hz 起）。
# 实测不切的时候 0–50 Hz 占了 7.4% 的能量、还有 ±600 的直流漂移在带偏 AGC。
HP_FC = 100.0

STEP_TABLE = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
    50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230,
    253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963,
    1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327,
    3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442,
    11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24686, 27086, 29794,
    32767,
]
INDEX_TABLE = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8]


# ============================================================ 音频元件
class ImaDecoder:
    """跨帧连续的 IMA/DVI ADPCM 解码器，输出 int16 列表。

    ATVV 是**高 nibble 先**（与 IMA 标准相反）。写反了会让
    直流偏移到 43.8% 满量程 —— 这是判断 nibble 顺序的决定性证据。
    """

    def __init__(self):
        self.predictor = 0
        self.index = 0

    def reset(self):
        self.predictor = 0
        self.index = 0

    def decode(self, data: bytes) -> list:
        pred, idx = self.predictor, self.index
        out = []
        for byte in data:
            for nib in (byte >> 4, byte & 0x0F):
                step = STEP_TABLE[idx]
                diff = step >> 3
                if nib & 1:
                    diff += step >> 2
                if nib & 2:
                    diff += step >> 1
                if nib & 4:
                    diff += step
                pred = pred - diff if nib & 8 else pred + diff
                if pred > 32767:
                    pred = 32767
                elif pred < -32768:
                    pred = -32768
                idx += INDEX_TABLE[nib]
                if idx < 0:
                    idx = 0
                elif idx > 88:
                    idx = 88
                out.append(pred)
        self.predictor, self.index = pred, idx
        return out


class DcBlocker:
    """一阶高通，抹掉遥控器麦克风的直流偏置。y[n]=x[n]-x[n-1]+a*y[n-1]"""

    def __init__(self, a=0.995):
        self.a = a
        self.x1 = 0.0
        self.y1 = 0.0

    def process(self, x):
        out = []
        for v in x:
            y = v - self.x1 + self.a * self.y1
            self.x1 = v
            self.y1 = y
            out.append(y)
        return out


class HighPass:
    r"""二阶高通（RBJ biquad）：把**不属于人声的低频**整段拿掉。

    为什么需要（实测数据）：把虚拟声卡线上的语音拿去算频谱，得到
        0–20 Hz 3.4% / 20–50 Hz 4.0% / 50–100 Hz 10.5% / 100–200 Hz 17.2%
    而对照（同一套分析跑标准语音）0–50 Hz 只有 1.1%。
    更要命的是**每 170 ms 的直流均值在 ±600 之间漂移**（满量程 32768）——
    那是 IMA ADPCM 在低码率下步长自适应慢留下的**缓慢漂移**，不是人声。

    它有两个直接危害：
      · 占掉了 AGC 的动态范围：AGC 盯的是**峰值**，而峰值被这个漂移/隆隆声顶着，
        于是增益被压低，真正的人声（300–3400 Hz）反而录得偏小；
      · 识别器看的是语音特征，这些低频纯属噪声。

    人声主体在 300–3400 Hz，男声基频最低到 ~85 Hz，所以切在 100 Hz 既安全又够用
    （电话带宽的标准做法是 300 Hz 起，ASR 前端一般 80–100 Hz 起）。
    """

    def __init__(self, fc=100.0, sr=16000.0, q=0.707):
        w0 = 2.0 * math.pi * fc / sr
        cw, sw = math.cos(w0), math.sin(w0)
        alpha = sw / (2.0 * q)
        b0, b1, b2 = (1.0 + cw) / 2.0, -(1.0 + cw), (1.0 + cw) / 2.0
        a0, a1, a2 = 1.0 + alpha, -2.0 * cw, 1.0 - alpha
        self.b0, self.b1, self.b2 = b0 / a0, b1 / a0, b2 / a0
        self.a1, self.a2 = a1 / a0, a2 / a0
        self.x1 = self.x2 = self.y1 = self.y2 = 0.0

    def process(self, x):
        out = []
        b0, b1, b2, a1, a2 = self.b0, self.b1, self.b2, self.a1, self.a2
        x1, x2, y1, y2 = self.x1, self.x2, self.y1, self.y2
        for v in x:
            y = b0 * v + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2
            x2, x1 = x1, v
            y2, y1 = y1, y
            out.append(y)
        self.x1, self.x2, self.y1, self.y2 = x1, x2, y1, y2
        return out

    def reset(self):
        self.x1 = self.x2 = self.y1 = self.y2 = 0.0


class Resampler3x:
    """16k → 48k：整数倍线性插值，跨块保持相位。"""

    def __init__(self, factor=3):
        self.f = factor
        self.prev = 0.0

    def process(self, x):
        if not x:
            return []
        out = []
        prev = self.prev
        f = self.f
        for v in x:
            step = (v - prev) / f
            cur = prev
            for _ in range(f):
                cur += step
                out.append(cur)
            prev = v
        self.prev = prev
        return out


class Agc:
    """极简自动增益：跟踪近段峰值，向目标电平靠拢（带上下限）。"""

    def __init__(self, target=0.35, lo=1.0, hi=12.0, decay=0.995):
        self.target, self.lo, self.hi, self.decay = target, lo, hi, decay
        self.peak = 0.0
        self.gain = 1.0
        self.blocks = 0

    def process(self, x):
        peak = 0.0
        for v in x:
            a = v if v >= 0 else -v
            if a > peak:
                peak = a
        self.peak = max(peak, self.peak * self.decay)
        if self.blocks % 20 == 0 and self.peak > 1e-4:
            want = self.target / self.peak
            self.gain = max(self.lo, min(self.hi, want))
        self.blocks += 1
        g = self.gain
        return [v * g for v in x]


class Sink:
    """把 PCM 写进虚拟声卡的输出端点（CABLE Input）。

    用 RawOutputStream + 阻塞写：不需要 numpy，也不需要处理回调缓冲区类型。
    待播缓冲刻意留小（~200ms）—— 采集和播放是两个独立时钟，
    速率微差会让积压一路涨，延迟就变成「听到几百毫秒前的声音」。
    """

    def __init__(self, device, gain=4.0, agc=True, soft_k=0.9, on_log=None):
        self.device = device
        self.gain = gain
        self.use_agc = agc
        self.soft_k = soft_k
        self.on_log = on_log or (lambda m: None)
        self.lock = threading.Lock()
        self.buf = bytearray()
        self.max_bytes = int(SR_OUT * 0.2) * 4      # 200ms 立体声 int16
        self.stream = None
        self.thread = None
        self.run_flag = threading.Event()
        self.alive = False                  # 出口是否可用（看护任务据此重建）
        self.decoder = ImaDecoder()
        self.dc = DcBlocker()
        self.hp = HighPass(HP_FC, SR_IN)     # ★ 去掉低频漂移/隆隆声，让 AGC 盯着人声
        self.rs = Resampler3x()
        self.agc = Agc()
        self.frames = 0
        self.underruns = 0

    def start(self):
        import sounddevice as sd
        self.stream = sd.RawOutputStream(device=self.device, samplerate=SR_OUT,
                                         channels=2, dtype="int16",
                                         blocksize=int(SR_OUT * 0.02))
        self.stream.start()
        self.run_flag.set()
        self.alive = True
        self.thread = threading.Thread(target=self._pump, daemon=True, name="audio-out")
        self.thread.start()

    def _pump(self):
        chunk = int(SR_OUT * 0.02) * 4              # 20ms 立体声 int16
        silent = b"\x00" * chunk
        fails = 0
        while self.run_flag.is_set():
            with self.lock:
                if len(self.buf) >= chunk:
                    data = bytes(self.buf[:chunk])
                    del self.buf[:chunk]
                else:
                    data = silent
                    self.underruns += 1
            try:
                self.stream.write(data)
                fails = 0
            except Exception:
                # 连续半秒都写不进去 = 设备被拔了/音频服务重启了 → 判掉线，
                # 让看护任务重建一条（开机时尤其常见）。
                fails += 1
                if fails > 25:
                    self.alive = False
                    return
                time.sleep(0.02)

    def feed_adpcm(self, frame: bytes):
        if not self.alive:
            return
        self.frames += 1
        pcm = self.decoder.decode(frame)
        x = self.dc.process(pcm)
        x = self.hp.process(x)                      # 高通：低频漂移在这里被拿掉
        x = self.rs.process(x)                      # -> 48k float
        if self.use_agc:
            x = self.agc.process([v / 32768.0 for v in x])
        else:
            x = [v / 32768.0 * self.gain for v in x]
        k = self.soft_k
        out = bytearray()
        for v in x:
            s = int(k * math.tanh(v / k) * 32767.0)
            if s > 32767:
                s = 32767
            elif s < -32768:
                s = -32768
            out += (s & 0xFFFF).to_bytes(2, "little") * 2      # 左右同相
        with self.lock:
            self.buf += out
            if len(self.buf) > self.max_bytes:                 # 超了丢最旧的
                del self.buf[:len(self.buf) - self.max_bytes]

    def reset(self):
        with self.lock:
            self.buf.clear()
        self.decoder.reset()
        self.dc.x1 = self.dc.y1 = 0.0
        self.hp.reset()
        self.rs.prev = 0.0

    def stop(self):
        self.alive = False
        self.run_flag.clear()
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
        if self.stream:
            try:
                self.stream.stop()
                self.stream.close()
            except Exception:
                pass
            self.stream = None


class MicRelay:
    """系统默认麦克风 → 同一个 CABLE Input 的实时直通。

    为什么需要：输入法把麦克风**钉死在配置里**（千问的 deviceId 且
    isDefault=false），改系统默认录音设备对它无效；而遥控器音频必须经
    虚拟声卡才能被输入法读到。于是让 CABLE 这一路在「按住键盘语音快捷键」
    时永远有声音 —— 日常用键盘说话照旧，其他应用仍走真实麦克风，互不影响。
    """

    def __init__(self, sink, on_log=None):
        self.sink = sink
        self.on_log = on_log or (lambda m: None)
        self.stream = None
        self.thread = None
        self.run_flag = threading.Event()
        self.active_holder = False          # 由 _alt_watch 置位
        self.device = None
        self.name = "?"
        self.sr = SR_OUT
        self._prev = 0.0
        self._t = 0.0
        self.frames = 0

    @staticmethod
    def _usable(d):
        """这个录音端点能不能当"直通源"。

        ★ 虚拟声卡自己的端点绝对不行：机器上很常见的一种配置是把系统默认
          录音设备就设成 `CABLE Output`（为了让输入法/微信听到遥控器）。
          这时候如果直通还去读"默认录音设备"，就等于**把虚拟声卡的输出
          再灌回它自己的输入** —— 自己喂自己。遥控器的声音会在声卡里
          叠上一层延迟副本（听起来发闷、像有混响），输入法的识别率会
          明显下降。所以这里必须把虚拟声卡/回环端点排除掉。
        """
        if d["max_input_channels"] <= 0:
            return False
        raw = d["name"]
        n = raw.lower()
        if _is_vb_audio(n) or "cable" in n:
            return False
        if "voicemeeter" in n or "point" in n:
            return False
        # 立体声混音 / What U Hear 这类是"回放的回环"，同样会自己喂自己
        if "stereo mix" in n or "what u hear" in n or "立体声混音" in raw:
            return False
        return True

    def probe(self):
        """挑一个**真实**麦克风当直通源（默认设备优先，但绝不选虚拟声卡）。"""
        import sounddevice as sd
        devs, hosts = sd.query_devices(), sd.query_hostapis()
        wasapi = [h for h in hosts if "wasapi" in h["name"].lower()]
        order, seen = [], set()

        def push(i):
            if i is None or i < 0 or i in seen or i >= len(devs):
                return
            seen.add(i)
            if self._usable(devs[i]):
                order.append(i)

        for h in wasapi:                       # 1) WASAPI 的默认录音设备（用户自己选的那个）
            push(h.get("default_input_device"))
        for i in range(len(devs)):             # 2) 其余 WASAPI 录音端点
            try:
                is_wasapi = "wasapi" in hosts[devs[i]["hostapi"]]["name"].lower()
            except Exception:
                is_wasapi = False
            if is_wasapi:
                push(i)
        for i in range(len(devs)):             # 3) 兜底：别的 host API 也行（延迟差一点，总比没有好）
            push(i)

        if not order:
            return False
        i = order[0]
        self.device = i
        self.name = devs[i]["name"]
        self.sr = int(devs[i].get("default_samplerate") or 0) or SR_OUT
        return True

    def start(self):
        import sounddevice as sd
        self.stream = sd.RawInputStream(device=self.device, samplerate=self.sr,
                                        channels=1, dtype="int16",
                                        blocksize=int(self.sr * 0.02))
        self.stream.start()
        self.run_flag.set()
        self.thread = threading.Thread(target=self._pump, daemon=True, name="mic-relay")
        self.thread.start()

    def _pump(self):
        step = self.sr / float(SR_OUT)
        while self.run_flag.is_set():
            try:
                data, _overflow = self.stream.read(int(self.sr * 0.02))
            except Exception:
                time.sleep(0.05)
                continue
            if not self.active_holder:
                self._t = 0.0
                continue
            samples = memoryview(data).cast("h")
            out = bytearray()
            pos = self._t
            n = len(samples)
            while pos < n - 1:
                i = int(pos)
                f = pos - i
                v = samples[i] * (1 - f) + samples[i + 1] * f
                s = int(v)
                out += (s & 0xFFFF).to_bytes(2, "little") * 2
                pos += step
            self._t = pos - n
            self._prev = samples[-1] if n else self._prev
            self.frames += 1
            with self.sink.lock:
                self.sink.buf += out
                if len(self.sink.buf) > self.sink.max_bytes:
                    del self.sink.buf[:len(self.sink.buf) - self.sink.max_bytes]

    def stop(self):
        self.run_flag.clear()
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
        if self.stream:
            try:
                self.stream.stop()
                self.stream.close()
            except Exception:
                pass
            self.stream = None


def _is_vb_audio(name):
    n = name.lower()
    return ("vb-audio" in n or "vbaudio" in n or "vb audio" in n)


def _score_render(idx, dev, apis):
    """给"可能是那根线的输出端"打分，分高者优先。

    ⚠ 优先顺序很重要：VB-CABLE 会建**两个**渲染端点 ——
      · "CABLE Input"（2 声道）这是规范的那一个，输入法读的 "CABLE Output" 就是它的对面；
      · "CABLE In 16 Ch"（16 声道）是另一个端点，不是输入法那一侧。
    所以必须让 2 声道那个赢：只按"CABLE In"给高分，会选中 16 声道那路
    —— 而 Windows 把规范端点改名成「扬声器 (2- VB-Audio Virtual Cable)」之后，
    "扬声器"这个名字一个关键字都不含，很容易被 16 声道那路挤掉。
    """
    n = dev["name"].lower()
    if dev["max_output_channels"] <= 0:
        return None
    if not _is_vb_audio(n):
        return None
    # 别家的产品：Voicemeeter 的 "Point" 系列也带 VB-Audio 的名字，但它不是我们要的线
    if "point" in n or "voicemeeter" in n:
        return None
    score = 0
    if "cable input" in n:
        score += 100            # 规范名，最好
    elif "16 ch" in n or "16ch" in n:
        score -= 40             # 16 声道那路：不是输入法读的那一侧
    else:
        score += 25             # 其他 VB-Audio 渲染端点（被改名成"扬声器"时就是这种）
    try:
        if apis[dev["hostapi"]]["name"].lower().startswith("windows wasapi"):
            score += 20         # WASAPI：延迟和质量都更好
    except Exception:
        pass
    return score


def find_cable():
    """找 VB-CABLE 的两端：输出=我们往里写的那一侧，输入=输入法读的那一侧。

    ⚠ **不能只认 "cable input" / "cable output" 这两个字样。**
    驱动被 PnP 重装（卸载后重启，Windows 从 DriverStore 里又把它装回来）之后，
    Windows 会把**渲染端点**改名成「扬声器 (2- VB-Audio Virtual Cable)」——
    名字里根本没有 "cable input"。后果是语音桥接找不到输出端点、完全没有声音，
    而设备在设备管理器里明明是好的。

    所以分两步：
      ① 先按规范名找 —— 绝大多数机器上就是它，行为完全不变；
      ② 找不到再按**厂商名**兜底：名字里有 vb-audio、有输出通道、且不是
         Voicemeeter 的 "Point" 那一侧；优先规范名 > 非 16 声道 > WASAPI。
    """
    import sounddevice as sd
    devs = sd.query_devices()
    apis = sd.query_hostapis()
    out_idx = in_idx = None
    # ① 规范名（保持原行为）。输入端要排除 Voicemeeter 的 "Point" 那一侧 ——
    #    它的名字里也带 "cable output"，但那是**另一个产品**的线，
    #    报给用户看会让人以为"输入法该选它"。
    for i, d in enumerate(devs):
        name = d["name"].lower()
        if "cable input" in name and d["max_output_channels"] > 0:
            out_idx = i
        if ("cable output" in name and d["max_input_channels"] > 0
                and "point" not in name and "voicemeeter" not in name):
            in_idx = i
    # ② 兜底：按厂商名找输出端
    if out_idx is None:
        best = None
        for i, d in enumerate(devs):
            s = _score_render(i, d, apis)
            if s is None:
                continue
            if best is None or s > best[0]:
                best = (s, i)
        if best is not None:
            out_idx = best[1]
    # ② 兜底：输入端（"CABLE Output ..." 通常不会被改名，但一并兜住）
    if in_idx is None:
        for i, d in enumerate(devs):
            n = d["name"].lower()
            if d["max_input_channels"] > 0 and _is_vb_audio(n) \
                    and "point" not in n and "voicemeeter" not in n:
                if in_idx is None or "cable output" in n:
                    in_idx = i
    return out_idx, in_idx


def cable_device_names():
    """给"状态显示"用：先给**我们真正会写入的那个端点**，再补输入端。

    app.py 的 cable_state() 靠它判断"声卡到底能不能用"，所以这里必须走
    find_cable() 那套（含兜底）逻辑 —— 两边判断不一致的话，就会出现
    "体检说没找到、清单说已装"这种自相矛盾的诊断。
    """
    try:
        import sounddevice as sd
        devs = sd.query_devices()
    except Exception:
        return []
    out_idx, in_idx = find_cable()
    names = []
    for i in (out_idx, in_idx):
        if i is not None:
            names.append(devs[i]["name"])
    if names:
        return names
    # 真的一个可用端点都没有：把名字里带 cable 的都列出来（至少让用户看到"有东西在"）
    return [d["name"] for d in devs if "cable" in d["name"].lower()]


# ============================================================ 语音键
def spec_to_vk(spec):
    """{'mode','key','mods'} -> (mode, [修饰 VK], 主键 VK)；认不出返回 None。"""
    key = keys.vk_of(spec.get("key"))
    if not key:
        return None
    mods = [v for v in (keys.vk_of(m) for m in (spec.get("mods") or [])) if v]
    return (spec.get("mode") or "hold"), mods, key


class VoiceKey:
    """把「语音键按下/松开」变成键盘动作。

    hold（按住）：先按修饰键再按主键，松开时反序抬起 —— 输入法的
                  「按住说话」要的就是这个。
    tap（按一下）：给 Windows 语音输入（Win+H）那种开关式快捷键。
    """

    def __init__(self, spec):
        self.spec = spec or {}
        parsed = spec_to_vk(self.spec)
        self.ok = parsed is not None
        self.mode, self.mods, self.key = parsed or ("hold", [], 0)
        self.down = False

    @property
    def label(self):
        names = [m for m in (self.spec.get("mods") or [])]
        return "+".join(names + [str(self.spec.get("key") or "")])

    def press(self):
        if not self.ok or self.down:
            return
        self.down = True
        for m in self.mods:
            keys.key_down(m)
        keys.key_down(self.key)

    def release(self):
        if not self.ok or not self.down:
            return
        self.down = False
        keys.key_up(self.key)
        for m in reversed(self.mods):
            keys.key_up(m)

    def tap(self):
        if not self.ok:
            return
        for m in self.mods:
            keys.key_down(m)
        keys.key_down(self.key)
        keys.key_up(self.key)
        for m in reversed(self.mods):
            keys.key_up(m)

    def clear_stuck(self):
        """启动时补一次抬起：上次进程在「按住」期间被杀，键会一直处于按下态。"""
        if not self.ok:
            return False
        vks = self.mods + [self.key]
        if not any(keys.key_is_down(v) for v in vks):
            return False
        keys.key_up(self.key)
        for m in reversed(self.mods):
            keys.key_up(m)
        return True


# ============================================================ 语音角色
class VoiceRole(threading.Thread):
    """独立线程里跑一个 asyncio 事件循环，保持 ATVV 长连接。"""

    def __init__(self, on_event, addr=ADDR_DEFAULT, audio=None, voice_spec=None,
                 relay=True):
        super().__init__(daemon=True, name="VoiceRole")
        self.on_event = on_event
        self.addr = addr
        cfg = dict(audio or {})
        self.gain = float(cfg.get("gain", 4.0))
        self.agc = bool(cfg.get("agc", True))
        self.want_relay = bool(relay)
        self.voice_spec = voice_spec or {"mode": "hold", "key": "RALT", "mods": []}
        self.voice = VoiceKey(self.voice_spec)
        self.stop_flag = threading.Event()
        self._poke = threading.Event()      # 遥控器有按键活动 → 立刻重试连接
        # ★ 链路守卫：只要系统 HID 正握着这条唯一的 BLE 链路，语音就**只**在
        #   「刚有按键活动」的窗口里尝试连接（见 _wait_hid_awake）。
        self.hid_probe = None               # callable() -> bool：系统 HID 是否在握着链路
        self._activity_at = 0.0             # 遥控器最近一次按键活动的时间
        self._gate_logged = 0.0             # 上一次"等唤醒"提醒的时间（限流用）
        self.sink = None
        self.relay_obj = None
        self.connected = False
        self.note = i18n.L("未启动", "Not started")
        self.sessions = 0
        self.frames = 0
        self.misses = 0
        self._session_frames = 0
        self._active = False
        self._cable_warned = False
        self._relay_warned = False
        self._audio_task = None
        self._watch = None
        self._client = None
        self._loop = None
        self._reopen_requested = False
        self._ctl = None                    # ATVV 控制特征（补发 GET_CAPS 用）
        self._caps_at = 0.0                 # 上次发 GET_CAPS 的时间（限流）
        self._last_press_frames = None      # 上一段按住收到的音频帧数
        self._ctrl_seen = 0                 # 控制特征回话条数（诊断用）
        self._extra = {}                    # 其他 notify 特征各收到几条（诊断用）
        self._ctl_resp = False              # GET_CAPS 该用带响应写还是无响应写
        self._awake_at = 0.0                # 本次会话建立时刻
        self._mic_reset_at = 0.0            # 上次发 MIC_CLOSE 的时间（限流）
        self._voice_held = False            # 逻辑上"语音键正被按住"（IME 热键处于按下态）
        self._voice_reheld = False          # 已被「20 秒固件硬掐」自动续录过一次
        self._press_time = 0.0             # 最近一次 0x04 按下的时刻（判断 20 秒超时用）

    # ---------- 对外 ----------
    def poke(self):
        """遥控器刚有按键活动 —— 现在它醒着，立刻重试一次连接。

        为什么关键：BLE 外设只在刚醒的一小段时间里能被连上（之后又睡，
        或被系统 HID 拿走那唯一的连接），而失败退避最长要等 45 秒 ——
        靠"等"就把窗口全错过去了。按键钩子（keys.KeyTap.on_activity）负责叫醒这里。

        ★ 这里还记下活动时刻：`_wait_hid_awake()` 用它判断"现在是不是那个窗口"。
        """
        self._activity_at = time.time()
        self._poke.set()
        # ★ 遥控器刚发过 HID 报文 = 它**确认醒着**，顺手把录音态补一次。
        #   真机上「放一会儿再按语音键没反应」就是录音态过期 —— 而那种时候遥控器
        #   连 0x04 都不发，只能由我们主动补（否则要等保活秒表走到）。
        #   限流 10 秒一次：HID 报文可能一秒钟来几十条，不能每条都写特征。
        #
        # ★ 这里**不再补发 GET_CAPS**，改成主动"开麦"（MIC_OPEN）。理由有二：
        #   ① GET_CAPS 是"能力协商"，只在建链时发一次就够；这台固件根本不回它，
        #      反复发属于对空气喊话。**更要命的是：真机上两次"语音全死"都紧跟在
        #      一次 GET_CAPS 之后**（13:36:06 与 14:11:56），而且都是在遥控器**空闲**
        #      的时候 —— 很像遥控器把这条报文当成非法命令、进了错误状态。
        #      既然不必要，就彻底不发。
        #   ② MIC_OPEN 是遥控器**本来就认**的命令（参考实现按下语音键时就发它），
        #      用来"把麦重新打开"是安全的。而 HID 有活动 = 遥控器确认醒着，
        #      正是试它的时候。
        if self.connected and time.time() - getattr(self, "_wake_rearm_at", 0.0) >= 10.0:
            self._wake_rearm_at = time.time()
            self._try_open_mic()

        # ★★ 按键后备重连（对齐参考实现的「普通按键后备」）。
        #   判据：**用户在按方向键**（说明人在用遥控器）＋**这次连接以来一次语音都
        #   没成功过** ＋ 已经过了 90 秒 —— 这三个条件同时成立，就说明遥控器的录音
        #   通道挂死了（最典型的成因：误按了静音键）。
        #
        #   为什么必须"重开整个语音会话"而不是只发 MIC_OPEN：实测（15:42~15:43）
        #   MIC_OPEN 连发 4 次（15:42:13 / 15:42:33 / 15:43:21 / 15:43:50），
        #   一次语音会话都没起来 —— 只在同一条链路上开麦是救不回来的。
        #   参考实现的 README 也写着「谷歌遥控器启动时遇到临时语音连接失败，可自动
        #   补连；含首次及普通按键后备，最多尝试五次」。
        #
        #   重开会走 _close_current()：那里现在**先发 MIC_CLOSE 再断链** —— 正是
        #   "把遥控器认为还开着的麦关掉"这一步，理论上也是解开挂起的关键。
        now = time.time()
        if (self.connected
                and not getattr(self, "_active", False)
                and self.sessions == getattr(self, "_sessions_at_connect", 0)
                and now - getattr(self, "_awake_at", 0.0) > 90.0
                and now - getattr(self, "_reopen_at", 0.0) > 60.0):
            self._reopen_at = now
            self._log("语音：这次连接以来一次语音都没成功，而遥控器明显在被使用 —— "
                      "重开语音会话（MIC_CLOSE → 断链 → 重连）。"
                      "这能解掉「误按静音键把录音通道挂起」的状态。")
            self.force_reconnect()

    def _try_open_mic(self, hold=1.5, quiet=False):
        """主动开一次麦；开完没人说话就把麦收回去（不留麦开着）。

        为什么需要它：遥控器一旦把麦克风关掉，就**不会再发 0x04**，于是我们永远
        等不到"按下"，也就永远不会发 MIC_OPEN —— 语音就这样彻底哑了。
        而"HID 方向键有活动"是唯一还能拿到的、说明遥控器醒着的信号，
        所以用它当触发器：每有一次方向键活动，就主动开一次麦试试。

        开完 hold 秒还没开始录音（`_active` 仍为 False）→ 发 MIC_CLOSE 收回去，
        免得麦一直开着（隐私）。
        """
        if not self.connected or getattr(self, "_ctl", None) is None:
            return
        if not self.atvv_cmd(MIC_OPEN_CMD):
            return
        if not quiet:
            self._log("语音：遥控器有按键活动 —— 主动开一次麦（MIC_OPEN），"
                      "看看能不能把录音通道叫醒")

        def _close_if_idle():
            if self.stop_flag.is_set():
                return
            if not getattr(self, "_active", False):
                self.atvv_cmd(self._mic_close_cmd())

        try:
            t = threading.Timer(hold, _close_if_idle)
            t.daemon = True
            t.start()
        except Exception:
            pass

    def repair(self, on_line=None):
        """一键修复语音僵死：关麦 → 开麦 → 看遥控器有没有回话。

        用于「界面显示已连接，但按语音键一点反应都没有」的状态。
        **不重启客户端、不动 HID 链路、不重新配对** —— 只在 ATVV 这一层来回两下。

        为什么要"来回两下"：遥控器一旦把麦克风关掉就不再发 `0x04`，我们也就永远
        等不到"按下"。显式 MIC_CLOSE（把状态清干净）再 MIC_OPEN（重新打开），
        是唯一能把它的状态机推回正轨的组合 —— 参考实现按下/松开时发的就是这两条。

        返回 True = 遥控器回来了（会话数增加了）；False = 没回来。
        """
        def say(msg):
            if on_line is not None:
                try:
                    on_line(msg)
                except Exception:
                    pass
            self._log(msg)

        if not self.connected:
            say(i18n.L("语音：还没连上 —— 先按一下遥控器任意键让它连上",
                       "Voice: not connected — press any remote button first"))
            return False

        sessions0 = self.sessions
        say(i18n.L("语音：开始修复 —— 关麦 → 开麦，等遥控器回话…",
                   "Voice: repairing — closing the mic, then opening it, waiting for the remote…"))
        self.atvv_cmd(self._mic_close_cmd())

        def _step2():
            if self.stop_flag.is_set() or not self.connected:
                return
            time.sleep(0.5)
            self.atvv_cmd(MIC_OPEN_CMD)
            time.sleep(3.0)
            if self.sessions > sessions0:
                say(i18n.L("语音：修好了 —— 遥控器已经开始回话，按住语音键试试",
                           "Voice: fixed — the remote is answering again, try the voice key"))
            else:
                say(i18n.L(
                    "语音：还是没回话 —— 遥控器的录音通道僵死了，软件侧救不回来。\n"
                    "恢复办法（实测有效，顺序别变）：\n"
                    "  1) 取出电池；\n"
                    "  2) 点界面上的「一键重配遥控器」删掉这台设备；\n"
                    "  3) 装回电池，重新配对。\n"
                    "⚠ 只取电池装回**不够** —— 实测那样会变成「已配对但连不上、"
                    "连上又马上断」，必须连设备一起删掉。",
                    "Voice: still silent — the recording channel is wedged and nothing on "
                    "the software side recovers it.\n"
                    "Recovery (measured to work; keep the order):\n"
                    "  1) pull the battery;\n"
                    "  2) use “Re-pair remote” in the UI to delete the device;\n"
                    "  3) put the battery back and pair again.\n"
                    "⚠ Pulling the battery alone is NOT enough — that leaves it "
                    "“paired but never connecting / dropping right after connecting”."))

        t = threading.Thread(target=_step2, daemon=True)
        t.start()
        return True

    def rearm(self):
        """手动补发 GET_CAPS —— 给界面/接口留的"一键救急"。

        什么时候用：语音键按了没反应，但日志里会话还在（`connected: True`）。
        这时不用重启客户端、也不用重新配对（那些动作都会打断 HID 链路），
        补一发 GET_CAPS 基本就能把录音态叫回来。
        """
        self._rearm_caps(min_gap=0.0, reason="manual")

    def _start_extend_keepalive(self, every=8.0, first=8.0):
        """录音期间持续发 `0E <sid>`（会话保活）—— **提前且频繁**地发。

        为什么改节奏（2026-10-27 实测根因）：
          原来 `time.sleep(20)` 之后再发第一次 —— 而固件会话寿命就是 ~20 秒，
          第一次保活刚好卡在死线上；更糟的是循环里是"先 sleep 后判断 `_active`"，
          如果固件在 20 秒整发了 `0x00` 把 `_active` 置否，这次保活就彻底没发出去，
          于是会话必然在 20 秒被掐，表现就是"按住语音键不到 20 秒输入法就停"。

          参考实现（chromecast_voice.py）靠「遥控器持续送音频」给固件计时器续命，
          所以它在 20 秒处续命能成功；本机这支 Google A3 **根本不送音频**，会话
          只能靠 `0E <sid>` 续，就必须**领先于死线**地发：先等 8 秒发第一次，
          之后每 8 秒发一次。这样固件看到的「距上次续命」永远 < 10 秒，不会到 20。

        间隔选 8 秒而非 20 秒：既给固件留足余量，又不会被 GATT 写延迟 / 进程调度
        把续命包顶到 20 秒死线上。
        """
        def _loop():
            # 第一次提前发（远在 20 秒死线之前），别先睡满 20 秒。
            if first and first > 0:
                time.sleep(first)
            while (not self.stop_flag.is_set()
                    and getattr(self, "_active", False)
                    and self.connected):
                cmd = self._mic_extend_cmd()
                if cmd:
                    self.atvv_cmd(cmd)
                time.sleep(every)
        try:
            t = threading.Thread(target=_loop, daemon=True)
            t.start()
        except Exception:
            pass

    def _mic_close_cmd(self):
        """关麦命令：带上**遥控器告诉我们的会话号**（对不上会被忽略）。"""
        sid = getattr(self, "_last_session_id", None)
        return bytes([0x0D, sid & 0xFF]) if sid is not None else MIC_CLOSE_CMD

    def _mic_extend_cmd(self):
        """会话保活（`0E <sid>`）：参考实现每 20 秒发一次维持录音会话（EXTEND_SECONDS）。
        我们以前从来不发 —— 会话可能因此过期，然后遥控器就再也不接受新的开麦请求。"""
        sid = getattr(self, "_last_session_id", None)
        return bytes([0x0E, sid & 0xFF]) if sid is not None else None

    def atvv_cmd(self, payload):
        """往 ATVV 控制特征写任意命令 —— 给我自己排查用的一把螺丝刀。

        真机排障时最缺的就是"能不能直接发一条命令看看"：每次都改代码、重启客户端，
        一次调试要等两三分钟。有了这个，一条 HTTP 就能试 `0D 00 00`（MIC_CLOSE）、
        `0C 00 00`（MIC_OPEN）、`0A 00 04 00 01`（GET_CAPS）。
        """
        ctl = getattr(self, "_ctl", None)
        client = self._client
        loop = getattr(self, "_loop", None)
        if ctl is None or client is None or loop is None:
            return False
        data = bytes(payload)

        async def _do():
            try:
                await client.write_gatt_char(
                    ctl, data, response=bool(getattr(self, "_ctl_resp", False)))
                self._log(f"语音：已发送 ATVV 命令 {data.hex(' ')}")
            except Exception as e:
                self._log(f"语音：ATVV 命令 {data.hex(' ')} 发送失败 "
                          f"{type(e).__name__}: {e}")

        try:
            loop.call_soon_threadsafe(lambda: asyncio.ensure_future(_do()))
        except Exception:
            return False
        return True

    def force_reconnect(self):
        """丢掉当前会话、立刻重连 —— 不重启客户端、不动 HID。

        什么时候用：会话显示"已连接"，但按语音键什么都收不到（录音态/订阅已经
        僵了）。重连会重新走一遍订阅，等于给这条链路换一份干净的状态。

        ★ 2026-10-27 15:49 修了一个隐蔽的坑：原来这里是 `await c.disconnect()`，
          **在 Windows 上这个 await 会挂住**（BLE 外设不回应时 WinRT 不返回），
          于是既没有"连接已断开"的日志、会话也不会结束，重连等于没发生 ——
          "按键后备重连"这个功能因此完全失效。
          现在改成：置一个标志让**会话循环自己收尾**（它会在 0.5 秒内看到），
          断开操作带 3 秒超时，超时也照样把会话拆掉。
        """
        c = self._client
        loop = getattr(self, "_loop", None)
        if c is None or loop is None:
            return False
        self._activity_at = time.time()
        self._poke.set()
        self._reopen_requested = True

        async def _do():
            try:
                await asyncio.wait_for(c.disconnect(), timeout=3.0)
            except Exception:
                pass

        try:
            loop.call_soon_threadsafe(lambda: asyncio.ensure_future(_do()))
        except Exception:
            return False
        return True

    # 这些特征的通知是**已知无害**的例行广播，记下来只是刷屏：
    #   00002a19 电量（每几十秒一次，值不变，约 0x5f）
    #   00002a05 服务变更、00002a31 扫描刷新（通常还是 Access Denied，订不上）
    # 把它们排除掉，`其他通知` 剩下的才是真正值得看的"未知报文"。
    _EXTRA_QUIET = ("00002a19", "00002a05", "00002a31")

    def _watch_extra(self, client, ch):
        """把一条"其它" notify 特征的来包记下来（每条最多 5 条）。"""
        uuid = str(ch.uuid).lower()[:8]
        if uuid in self._EXTRA_QUIET:
            return

        def on_val(_c, data, _uuid=uuid):
            n = self._extra.get(_uuid, 0)
            if n >= 5:
                return
            self._extra[_uuid] = n + 1
            loop = getattr(self, "_loop", None)
            msg = f"语音：其他通知 {_uuid} = {bytes(data).hex(' ')}"
            if loop is not None:
                try:
                    loop.call_soon_threadsafe(self._log, msg)
                except Exception:
                    pass

        asyncio.ensure_future(self._safe_sub(client, ch, on_val, uuid))

    async def _safe_sub(self, client, ch, fn, uuid):
        try:
            await client.start_notify(ch, fn)
        except Exception as e:
            self._log(f"语音：订阅 {uuid} 失败（{type(e).__name__}: {e}）")

    def _hid_gate_state(self):
        """把 `hid_probe()` 归一成三态：`ok` / `reconnecting` / `absent`。

        兼容两种回调：老式返回 True/False 的、和新式返回三态字符串的
        （app._hid_state）。老式 True 当 `ok`、False 当 `absent`。
        """
        fn = self.hid_probe
        if fn is None:
            return "absent"
        try:
            st = fn()
        except Exception:
            return "absent"
        if st in ("ok", "reconnecting", "absent"):
            return st
        return "ok" if st else "absent"

    async def _wait_hid_awake(self):
        """守门：系统 HID 握着链路、而遥控器在睡 —— 这时**绝不去建链**。

        真机血泪（这条比任何一处修复都重要）：

          · BLE 外设同一时间只接受**一个**客户端；
          · 这支遥控器只在「它和已配对的 Windows 之间那条链路」上暴露完整服务表
            （10 个，含 ab5e0001 ATVV）。我们自己新建一条链路时，枚举结果只剩
            5 个基础服务（1800/1801/180a/180f/1813），ATVV 整个消失 ——
            日志就是「缺少 ATVV 特征」，看着特别像"这支遥控器没有语音功能"；
          · 真正的灾难是它会**把系统 HID 挤掉**：语音每 3 秒发起一轮连接，每轮都
            留一条半开连接在蓝牙栈里，Windows 的 HID 再也握不上那条链路 ——
            于是"按语音键没反应"过几分钟就变成"连方向键都不动了"。

        三态处理：

          · `absent`        —— 没走本地直读，没有"抢链"这回事，语音自己连（老行为）；
          · `reconnecting`  —— **一步都不许动**。换电池 / 重新配对之后 Windows 要重建
                               HID 子设备，链路会"连上又断"好几轮；这时插进去建链，
                              会让重建过程无限拉长（蓝牙里看着"连上就断"就是这个）；
          · `ok`            —— 只在「按键活动后 20 秒内」尝试，其余时间安静等着；
                               且按键后还要再等 HID_POST_KEY_SETTLE_S，让 Windows
                               先把**加密**链路握稳（抢在它前面只会拿到未加密的新链，
                               那种链上遥控器只给 5 个基础服务，ATVV 整个消失）。
        """
        if self.hid_probe is None:
            return
        waited = 0.0
        awake_since = None      # 进入"按键醒着"窗口的时刻，配合 HID_SETTLE_CAP_S
        while not self.stop_flag.is_set():
            st = self._hid_gate_state()
            if st == "absent":
                return
            if st == "reconnecting":
                # 让开重建过程，并把按键窗口作废 —— 否则刚重建完就会用旧窗口硬连
                self._activity_at = 0.0
                now = time.time()
                if now - self._gate_logged >= 30.0:
                    self._gate_logged = now
                    self._log("语音：系统 HID 正在重建（遥控器刚换了电池 / 重新配对？）"
                              "—— 先不碰链路，等它稳定")
                    self.note = i18n.L("等 HID 稳定（遥控器正在重连）",
                                       "Waiting for the HID link to settle")
                    self._emit("status", {"connected": False, "note": self.note})
                await asyncio.sleep(0.5)
                waited += 0.5
                continue
            if time.time() - self._activity_at <= HID_AWAKE_WINDOW_S:
                # ★ 按键后先等 Windows 把**加密**链路握稳（见 HID_POST_KEY_SETTLE_S）。
                #   抢在它前面连上去，拿到的是未加密的新链 —— 只有 5 个基础服务，
                #   连 1812(HID) 都没有，日志是"缺少 ATVV"，看着像遥控器没语音功能。
                #   上限 HID_SETTLE_CAP_S：用户连按方向键时活动时刻会被一次次刷新，
                #   没有这个上限就永远等不到。
                if awake_since is None:
                    awake_since = time.time()
                if (time.time() - self._activity_at < HID_POST_KEY_SETTLE_S
                        and time.time() - awake_since < HID_SETTLE_CAP_S):
                    await asyncio.sleep(0.2)
                    continue
                if waited >= 1.0:
                    self._log(f"语音：系统 HID 已握住链路（等了 {waited:.0f} 秒）"
                              f"—— 开始建语音连接")
                return
            awake_since = None
            # ★ 提示语要**立刻**切过来，不能等 60 秒的日志节流。否则刚重启 / 刚重配完
            #   之后，界面会一直挂着"系统 HID 正在重建（遥控器刚换了电池 / 重新配对？）"，
            #   明明链路已经握住了，看起来却像又坏了（2026-10-27 13:32 实测：
            #   13:31:48 集合就打开了，13:32:05 界面还写着"正在重建"）。
            if getattr(self, "_gate_note", "") != "wait":
                self._gate_note = "wait"
                self.note = i18n.L("等遥控器按键唤醒（按任意键）",
                                   "Waiting for a remote button press")
                self._emit("status", {"connected": False, "note": self.note})
            now = time.time()
            if now - self._gate_logged >= 60.0:
                self._gate_logged = now
                if waited <= 0.0:
                    self._log("语音：等遥控器醒一次 —— 先按一下遥控器任意键，"
                              "让系统 HID 握住这条唯一的蓝牙链路，语音才连得上"
                              "（不按键硬连只会把 HID 挤掉，两个一起失灵）")
                else:
                    self._log(f"语音：已等 {waited:.0f} 秒还没等到按键 —— "
                              f"按一下遥控器任意键即可")
            await asyncio.sleep(0.5)
            waited += 0.5

    async def _maybe_unstick(self):
        """连续几次"扫不到广播"之后**自动解卡**：把蓝牙关开一次。

        只在**确认特征**时动手，并且处处留退路：
          · 连续 ≥3 次「没扫到广播」（= 系统 HID 攥着唯一那条连接）才触发；
          · 限流：10 分钟最多一次（别把用户蓝牙反复关开）；
          · 用 Radio API（和设置里那个开关同一机制、不要管理员），**每次都读回状态确认**；
          · 关开失败/开不回来 → 日志里立刻给出手动补救（设置里打开蓝牙 / 设备管理器启用）。
        可用 `voice` 配置里的 `auto_unstick: false` 关掉这个行为。
        """
        if not bool((self.voice_spec or {}).get("auto_unstick", True)):
            return
        if getattr(self, "_stuck", 0) < 3:
            return
        now = time.time()
        if now - getattr(self, "_unstuck_at", 0.0) < UNSTICK_COOLDOWN:
            return
        self._unstuck_at = now
        self._stuck = 0
        self._log(i18n.L("语音：连续几次都扫不到广播 —— 自动把蓝牙关开一次解卡"
                         "（蓝牙设备会断开几秒，马上恢复）…",
                         "Voice: several scans in a row found no advertisement — auto-cycling "
                         "Bluetooth to unstick it (Bluetooth devices drop for a few seconds)…"))
        try:
            kind, detail = await unstick_bluetooth()
        except Exception as e:
            kind, detail = "failed", f"{type(e).__name__}: {e}"
        if kind == "restarted":
            self._log(i18n.L(f"语音：蓝牙已关开一次（{detail}）—— 继续重连。"
                             f"若还不行，请把遥控器**电池取出 10 秒**再装回。",
                             f"Voice: Bluetooth was cycled ({detail}) — reconnecting. If it still "
                             f"fails, take the remote's battery out for 10 seconds."))
        elif kind == "turned-on":
            self._log(i18n.L(f"语音：蓝牙原本是关的，已帮你打开（{detail}）",
                             f"Voice: Bluetooth was off; turned it on ({detail})"))
        elif kind == "unavailable":
            self._log(i18n.L(f"语音：自动解卡用不了（{detail}）—— 请手动在「设置 → 蓝牙」里"
                             f"关开一次，或把遥控器电池取出 10 秒。",
                             f"Voice: auto-unstick is unavailable ({detail}) — cycle Bluetooth by "
                             f"hand in Settings, or take the remote's battery out for 10 seconds."))
        else:
            self._log(i18n.L(f"语音：⚠ 自动解卡没能把蓝牙开回来（{detail}）",
                             f"Voice: ⚠ auto-unstick could not turn Bluetooth back on ({detail})"))
        self._poke.set()                    # 立刻再试一次连接

    def set_addr(self, addr):
        """遥控器蓝牙地址热更新。

        ⚠ 以前这里没有：界面里把地址改好、保存之后，**运行中的语音角色还用着旧地址**，
        表现就是"地址明明填对了，语音键还是没反应"，非得重启客户端才行。
        返回 True 表示地址真的变了（调用方拿来决定要不要记日志 / 立刻重连）。
        """
        new = (addr or "").strip()
        if new == (self.addr or "").strip():
            return False
        self.addr = new
        self._addr_warned = False
        self._no_addr = not new
        self._fails = 0
        self.poke()                      # 停止退避，马上按新地址试一次
        return True

    def _emit(self, kind, payload=None):
        try:
            self.on_event(kind, payload)
        except Exception:
            pass

    def _log(self, msg):
        self._emit("log", msg)

    def set_voice_spec(self, spec):
        self.voice_spec = spec or self.voice_spec
        self.voice = VoiceKey(self.voice_spec)

    # ---------- 线程主体 ----------
    def run(self):
        try:
            # 监听线程里必须自己初始化 COM，否则 WinRT 会报
            # "Illegal attempt to resolve or release an IAgileReference after uninitializing COM"
            ctypes.windll.ole32.CoInitializeEx(None, 0x0)      # COINIT_MULTITHREADED
        except Exception:
            pass
        try:
            asyncio.run(self._main())
        except Exception as e:
            self._emit("status", {"connected": False,
                                  "note": i18n.L(f"语音线程退出：{e}",
                                                 f"Voice thread exited: {e}")})

    async def _main(self):
        self._loop = asyncio.get_running_loop()
        if self.voice.clear_stuck():
            self._log("语音键：清掉上次残留的按下状态")

        # ★ 音频出口交给「看护任务」，不在启动这一刻一锤定音。
        #   开机自启时，虚拟声卡 / Windows 音频服务往往比我们晚就绪；
        #   只在启动时 find_cable() 一次的话，找不到就**永远**没声音 ——
        #   这正是「开机后按语音键没反应」的真因。现在改成每 5 秒重试，
        #   声卡一就绪就自动接上，中途掉了也会重建。
        self._audio_task = asyncio.ensure_future(self._audio_supervisor())
        self._watch = asyncio.ensure_future(self._alt_watch())

        try:
            await self._loop_sessions()
        finally:
            for t in (self._watch, self._audio_task):
                if t:
                    t.cancel()
            if self.relay_obj:
                self.relay_obj.stop()
                self.relay_obj = None
            if self.sink:
                self.sink.stop()
                self.sink = None
            self.voice.release()

    async def _audio_supervisor(self):
        """看护「音频出口 + 内置麦克风直通」：没有就建，坏了就重建。"""
        while not self.stop_flag.is_set():
            if self.sink is not None and not self.sink.alive:
                self._log("语音：音频出口掉线，正在重开…")
                self.sink.stop()
                self.sink = None
                if self.relay_obj:
                    self.relay_obj.stop()
                    self.relay_obj = None

            if self.sink is None:
                out_idx, _in_idx = find_cable()
                if out_idx is None:
                    if not self._cable_warned:
                        self._cable_warned = True
                        self.note = i18n.L("等虚拟声卡就绪…",
                                           "Waiting for the virtual audio cable…")
                        self._emit("status", {"connected": False, "note": self.note})
                        self._log("语音：暂时找不到虚拟声卡 VB-CABLE"
                                  "（开机后声卡常比程序晚就绪）—— 每 5 秒重试")
                else:
                    try:
                        s = Sink(out_idx, gain=self.gain, agc=self.agc,
                                 on_log=self._log)
                        s.start()
                        self.sink = s
                        self._cable_warned = False
                        # ★ 把**设备名**一起写进日志：用户最常问的就是"虚拟声卡的 in/out
                        #   到底哪个是哪个"。日志里直接说清"程序往哪写、输入法该读哪个"，
                        #   能省一整轮来回（真机上被问过两次）。
                        dev_out = ""
                        try:
                            import sounddevice as sd
                            dev_out = str(sd.query_devices(out_idx)["name"])
                        except Exception:
                            pass
                        try:
                            _ci, _co = find_cable()
                        except Exception:
                            _ci = _co = None
                        self._log("语音：音频出口已开启（"
                                  + ("AGC" if self.agc else f"固定增益 {self.gain}x")
                                  + "）" + (f" → 写入「{dev_out}」" if dev_out else "")
                                  + (f"；输入法那边请选「{_dev_name(_co)}」（录制设备）"
                                     if _co is not None else ""))
                    except Exception as e:
                        if not self._cable_warned:
                            self._cable_warned = True
                            self._log(f"语音：打开音频出口失败 "
                                      f"{type(e).__name__}: {e}（每 5 秒重试）")

            if self.want_relay and self.sink is not None and self.relay_obj is None:
                try:
                    r = MicRelay(self.sink, on_log=self._log)
                    if r.probe():
                        r.start()
                        self.relay_obj = r
                        self._log(f"语音：麦克风直通已就绪（{r.name}，"
                                  f"按住键盘语音快捷键时转发）")
                        self._relay_warned = False
                    elif not self._relay_warned:
                        self._relay_warned = True
                        self._log("语音：没找到可用的真实麦克风，直通暂时不开"
                                  "（系统默认录音设备若是 CABLE Output，"
                                  "直通会自己喂自己，所以这里故意不用）")
                except Exception:
                    pass
            elif not self.want_relay and self.relay_obj is not None:
                self.relay_obj.stop()
                self.relay_obj = None

            await asyncio.sleep(5)

    async def _alt_watch(self):
        """轮询键盘语音键状态，决定麦克风直通开不开。

        ⚠ 遥控器正在送音频时必须关掉直通：遥控器的声音本来就是从
        CABLE 这一路出去的，这时候再直通一路进来，输入法会同时听到
        **同一句话的两份**（真实麦克风还会早到几百毫秒），识别率会
        明显变差 —— 这个「双份」曾被认为是"千问不认虚拟声卡"。
        所以：只有「按住键盘语音键、且遥控器没在说话」时才直通。
        """
        vks = self.voice.mods + [self.voice.key] if self.voice.ok else []
        while not self.stop_flag.is_set():
            if self.relay_obj and vks:
                # `all` 而不是 `any`：组合键要**整组**按住才算"在按语音键"。
                # 写成 any 的话，只要碰一下 Ctrl（很多组合键的修饰键）就开直通，
                # 真实麦克风会被悄悄混进虚拟声卡里。
                held = all(keys.key_is_down(v) for v in vks)
                self.relay_obj.active_holder = bool(held) and not bool(
                    getattr(self, "_active", False))
            await asyncio.sleep(0.05)

    # ---------- 连接 ----------
    def _new_client(self, dev, timeout):
        """统一构造 BleakClient。

        明确要求 UNCACHED 服务发现：bleak 在 Windows 上默认调的
        GetGattServicesAsync() 无参重载是**走缓存**的，缓存有机会骗人。
        （它不是「缺少 ATVV」的原因，但少一个变量总是好的。）
        老版本 bleak 不认这个关键字就退回默认。
        """
        from bleak import BleakClient
        try:
            return BleakClient(dev, timeout=timeout,
                               winrt={"use_cached_services": False})
        except TypeError:
            return BleakClient(dev, timeout=timeout)

    async def _connect_wait(self, client, timeout):
        """超时后**不等**这个连接：bleak 的 WinRT 连接底层是 COM IAsyncAction，
        被 asyncio.wait_for 取消时不会真正中断（会卡死 30s+）。
        所以只等一段时间，没完成就放手，另挂回调收尾。"""
        task = asyncio.ensure_future(client.connect())
        done, _ = await asyncio.wait({task}, timeout=timeout)
        if done:
            try:
                task.result()
                return True
            except Exception as e:
                self._log(f"语音：连接失败 {type(e).__name__}: {e}")
                return False
        self._log(f"语音：连接超时（{timeout:.0f}s）—— 遥控器多半在休眠")
        task.add_done_callback(lambda t: asyncio.ensure_future(self._reap(t, client)))
        return False

    async def _reap(self, task, client):
        """迟到的连接：真连上了就关掉，别占着设备。"""
        try:
            await task
        except Exception:
            return
        try:
            if client.is_connected and client is not self._client:
                await client.disconnect()
        except Exception:
            pass

    async def _close_current(self):
        """开新会话前，把上一条连接彻底关掉。

        ★ 这是「缺少 ATVV 特征」死循环的真因：遥控器的 GATT 通道只给第一个
        客户端完整服务表，第二个客户端只剩 4 个基础服务。本进程里只要挂着
        一条没关干净的会话（典型来源：connect 超时后那个迟到的连接），之后
        每次新连接都会被当成第二个客户端 —— 重连治不好，只有换进程才行。
        """
        c, self._client = self._client, None
        if c is None:
            self._ctl = None
            return
        # ★★ 断开前**先发 MIC_CLOSE**（2026-10-27 14:11 血泪）。
        #   遥控器如果以为"麦还开着"，而我们这边直接把链路断了，它的状态机就会
        #   僵死 —— 之后无论重连多少次、换多少个进程，它都不再发 0x04。
        #   真机实测：14:11:56 一次 force_reconnect（没发 MIC_CLOSE 就断）之后，
        #   14:16 / 14:21 / 14:31 三次重新建链，遥控器一次 0x04 都没再发过 ——
        #   而在 14:11 之前它是好的（58 帧、74 帧）。
        #
        #   参考实现对这一点非常明确（remotemic-src/RC003，
        #   ble_transport_winrt.py 的 send_mic_close_threadsafe）：
        #   "before it ever touches GATT resources (MIC_CLOSE, CCCD,
        #    characteristic/service/device disposal)" —— 先关麦，再拆资源。
        #   我们以前是反的：直接 disconnect。
        try:
            # ★ 必须在 self._ctl / self._client 还指着旧会话的时候发 —— 发完再清。
            self.atvv_cmd(self._mic_close_cmd())
            await asyncio.sleep(0.25)
        except Exception:
            pass
        self._ctl = None
        try:
            await c.disconnect()
        except Exception:
            pass

    async def _loop_sessions(self):
        while not self.stop_flag.is_set():
            # ★ 每一轮都先过守卫：系统 HID 握着链路时，语音必须等「刚有按键」这个窗口，
            #   否则会把自己和 HID 一起搞掉（详见 _wait_hid_awake 的注释）。
            await self._wait_hid_awake()
            if self.stop_flag.is_set():
                break
            try:
                await self._session()
            except asyncio.CancelledError:
                raise
            except (ImportError, ModuleNotFoundError) as e:
                # 依赖没装：每 3 秒重试一万次也没用，只会把日志刷爆。
                # 明确停下来说清楚该干什么。
                self.note = i18n.L(
                    f"缺依赖（{e}）—— 装完依赖重启客户端即可",
                    f"Missing dependency ({e}) — install dependencies, then restart the client")
                self._emit("status", {"connected": False, "note": self.note})
                self._log(f"语音：{self.note}；本角色已停止（不会反复重试）")
                return
            except Exception as e:
                self._log(f"语音：连接异常 {type(e).__name__}: {e}")
                hint = pairing_hint(type(e).__name__, str(e))
                if hint and hint != getattr(self, "_last_hint", None):
                    self._last_hint = hint
                    self._log(hint)
            if self.stop_flag.is_set():
                break
            self._emit("status", {"connected": False, "note": self.note})
            # ★ 退避：原来固定 3 秒重试一轮，一晚上能发起上万次连接，而每次超时都是
            #   一条"半开"的 WinRT 连接留在蓝牙栈里 —— 反倒更容易把设备拖在"已连接"
            #   状态、再也不广播。改成成功即重置、失败越久越慢（3→6→12→24→45 封顶）。
            if getattr(self, "_no_addr", False):
                # 还没填遥控器地址：这不是"连不上"，别拿它刷"已连续 N 次没连上"
                # （新用户首启会看到这条，容易误读成程序坏了）。
                fails = getattr(self, "_fails", 0)
                delay = 10.0
            else:
                fails = 0 if getattr(self, "_session_ok", False) else getattr(self, "_fails", 0) + 1
                self._fails = fails
                delay = min(3.0 * (2 ** min(fails, 4)), 45.0)
                if fails >= 8 and fails % 8 == 0:
                    self._log(f"语音：已连续 {fails} 次没连上，退避到 {delay:.0f} 秒；"
                              f"若一直这样，关开一次蓝牙开关再重试")
            # 等退避，但遥控器一有按键活动就立刻重试（那会儿它刚醒，成功率最高）
            end = time.time() + delay
            while (time.time() < end and not self.stop_flag.is_set()
                   and not self._poke.is_set()):
                await asyncio.sleep(0.2)
            if self._poke.is_set():
                self._poke.clear()
                # ★ 上一次拿到的是"未加密的新链"（只有 5 个基础服务）时不能立刻重来：
                #   刚让回去的链路还没被 Windows 握稳，再插一次只会又抢到一条新链，
                #   三张一样的坏表就是这么连着出来的。退一下，给它时间加密。
                if getattr(self, "_last_unpaired", False):
                    self._log(f"语音：刚抢到的是未加密链路 —— 先退 {UNPAIRED_RETRY_DELAY_S:.0f} 秒，"
                              f"等 Windows 把加密链路握稳再试（别急，急着连只会又抢一条新链）")
                    end2 = time.time() + UNPAIRED_RETRY_DELAY_S
                    while (time.time() < end2 and not self.stop_flag.is_set()):
                        await asyncio.sleep(0.2)
                    self._poke.clear()
                else:
                    self._log("语音：遥控器有按键活动 —— 不再退避，立刻重试连接")

    async def _device_with_details(self):
        """不靠广播拿到设备对象，塞进 BLEDevice.details。

        为什么必须这么做（真机实测）：BLE 外设只接受**一个**连接。Windows 的 HID
        栈一旦拿住遥控器，它就不再广播 —— 同一秒里"按键能进 Windows、扫描却什么都
        看不到"。而原来的流程是「details=None 硬连 → 扫广播 → 再连」，于是只要
        HID 拿着连接，**扫不到就永远连不上**，一卡就是一整晚（重启程序、重启电脑都
        治不好，因为开机自启起来立刻又进这个循环）。

        Windows 自己有配对记录，`FromBluetoothAddressAsync` 拿设备对象**不需要广播**，
        把对象塞进 details 后 bleak 就能直接连（实测这一步能走到真正的 connect）。
        """
        try:
            from winrt.windows.devices.bluetooth import BluetoothLEDevice
            from bleak.backends.device import BLEDevice
        except Exception:
            return None
        try:
            n = int(str(self.addr).replace(":", "").replace("-", ""), 16)
        except Exception:
            return None
        try:
            dev = await BluetoothLEDevice.from_bluetooth_address_async(n)
        except Exception as e:
            self._log(f"语音：按地址取设备对象失败 {type(e).__name__}: {e}")
            return None
        if dev is None:
            return None
        h = "%012X" % int(dev.bluetooth_address)
        mac = ":".join(h[i:i + 2] for i in range(0, 12, 2))
        return BLEDevice(mac, dev.name or "Chromecast Remote", dev)

    async def _session(self):
        from bleak import BleakScanner
        from bleak.backends.device import BLEDevice

        self._session_ok = False
        if not (self.addr or "").strip():
            # 出厂默认地址是空的（不把开发机那支遥控器的地址写进公开仓库），
            # 所以新用户第一次启动会走到这里：说清楚该干什么，别刷超时。
            self._no_addr = True
            if not getattr(self, "_addr_warned", False):
                self._addr_warned = True
                self._log("语音：还没填遥控器蓝牙地址 —— 到「设置」点「扫描」选中它，或直接粘贴地址")
            self.note = i18n.L("还没填遥控器蓝牙地址（到设置页扫描一次）",
                               "No remote address yet (scan it on the Settings page)")
            return
        self._no_addr = False
        await self._close_current()
        self._log(f"语音：连接遥控器 {self.addr} …")
        dev = await self._device_with_details()
        if dev is None:
            dev = BLEDevice(self.addr, "Chromecast Remote", None)
        client = self._new_client(dev, 3.0)
        self._client = client
        ok = await self._connect_wait(client, 3.0)

        if not ok:
            # 兜底：扫一次（只在设备正好在广播时有用；HID 拿着连接时它不会广播）
            self._log("语音：直连没成，扫一次看它在不在广播（它平时不广播，属正常）…")
            found = None
            try:
                found = await BleakScanner.find_device_by_address(self.addr, timeout=4.0)
            except Exception as e:
                self._log(f"语音：扫描异常 {type(e).__name__}: {e}")
            if found is None:
                self._log("语音：没扫到广播（多半被系统 HID 拿着连接）—— 重试连接")
                # ★ 这就是"按键能用、只有语音不行"的特征：系统 HID 攥着那唯一一条 BLE 连接，
                #   遥控器因此不广播，我们也建不起自己的 GATT 连接。连续几次都这样 → 自动解卡
                #   （用 Windows 的 Radio API 把蓝牙关开一次；跟设置里那个开关同一个机制，
                #    不需要管理员，也不会把电台留在禁用状态）。
                self._stuck = getattr(self, "_stuck", 0) + 1
                await self._maybe_unstick()
            client = self._new_client(found or dev, 10.0)
            self._client = client
            ok = await self._connect_wait(client, 10.0)

        if not ok:
            self.note = i18n.L(
                "未连上（按一下遥控器任意键会重试；一直不行就点「重置蓝牙电台」）",
                "Not connected (press any remote button to retry; if it keeps failing use "
                "“Reset Bluetooth radio”)")
            return
        self._log(f"语音：已连接遥控器 {self.addr}")
        self._session_ok = True
        self._stuck = 0                     # 连上了 → "卡住"计数清零（自动解卡的依据）

        chars, uuids = [], []
        try:
            for s in client.services:
                uuids.append(str(s.uuid).lower()[:8])
                chars.extend(s.characteristics)
        except Exception as e:
            self._log(f"语音：枚举服务失败 {type(e).__name__}: {e}")
            await self._close_current()
            return

        def find(prefix):
            for c in chars:
                if str(c.uuid).lower().startswith(prefix):
                    return c
            return None

        audio, status = find(ATVV_AUDIO), find(ATVV_STATUS)
        ctl = find(ATVV_CTL)
        if not (audio and status):
            self.misses += 1
            self._last_unpaired = True      # 供外层退避用：下次别急着立刻重连
            self._log(f"语音：缺少 ATVV 特征（本次枚举到 {len(uuids)} 个服务："
                      f"{', '.join(uuids) or '空'}）")
            # ★ 只在基础服务里转圈 = 这条链路是**我们自己新建**的（不是复用系统 HID 那条）。
            #   这时候最该做的是立刻松手、把链路让回 HID，等下一次按键再试 —— 而不是
            #   连着重试。原来这里连续重试，正是"语音键没反应 → 方向键也不动了"的成因。
            self._activity_at = 0.0
            # ★★ 关键判据：一条真正的 HID 链路里一定有 00001812（HID over GATT）。
            #   连 1812 都没有 → 这条链**连 HID 都不是**，它不是"我们抢了 HID 的链"，
            #   而是一条**没通过配对/加密协商**的新链。遥控器只对已加密的链暴露
            #   1812(HID) 与 ab5e(ATVV)；未加密时只给 1800/1801/180a/180f/1813。
            #   真机实证（13:18 / 13:22 三次都是同一张 5 服务表）：蓝牙电台关开一次
            #   之后 Windows 侧的配对密钥失效，此时光等、光重试都不会好 —— 必须在
            #   系统里删设备重新配对。原先把这种情况误报成"这遥控器没有语音服务"。
            paired = "00001812" in uuids
            if self.misses < 3:
                self._log("语音：这条链路不是系统 HID 那条（自己新建的链看不到 ATVV）"
                          "—— 已断开让回 HID，请按一下遥控器任意键，我再试一次")
            elif not paired:                      # 配对/加密状态丢了
                if not getattr(self, "_unpaired_hinted", False):
                    self._unpaired_hinted = True
                    self._log(i18n.L(
                        "语音：这条链上连 HID（00001812）都没有 —— 配对/加密状态丢了，"
                        "遥控器只肯把基础服务交给我（未加密的链它不给 HID，也不给 ATVV）。"
                        "光等不会自己好：请到「设置 → 蓝牙和其他设备」把谷歌遥控器"
                        "**删除设备**，取出电池等 10 秒，再重新配对一次。",
                        "Voice: this link does not even expose HID (00001812) — the "
                        "pairing/encryption state is gone, so the remote only hands out "
                        "the basic services (an unencrypted link gets neither HID nor "
                        "ATVV). Waiting will not fix it: remove the remote in Settings → "
                        "Bluetooth & devices, pull the battery for 10 s, and pair again."))
            else:
                if not getattr(self, "_variant_hinted", False):
                    # ★ 连续多次、每次都只有通用服务（1800/1801/180a/180f）、没有 ab5e…
                    #   → 这支遥控器**根本没有语音服务**。真机上见过：同一款
                    #   "G9N9N/GA01919"兼容款，不同批次差别很大 —— 有的带语音，有的只有
                    #   HID 按键。这句话直接给用户一个结论和一条出路，省得反复怀疑软件。
                    self._variant_hinted = True
                    self._log(i18n.L(
                        "语音：连续 3 次都只看得到基础服务、没有 ATVV —— 这支遥控器多半"
                        "**没有语音服务**（它多半不是原装 G9N9N / GA01919；兼容款批次差异很大）。"
                        "按键映射不受影响。若你确认它有语音，请点「重启」重新拉起客户端，"
                        "并按一下遥控器任意键再试。",
                        "Voice: three attempts in a row showed only the basic services and no "
                        "ATVV — this remote most likely has **no voice service** (probably not a "
                        "genuine G9N9N / GA01919). Key mapping is unaffected. If you are sure it "
                        "does have voice, click “Restart” and press any remote button."))
            await self._close_current()
            return

        self.misses = 0
        self._unpaired_hinted = False      # 这次真连上了 → 下次再丢配对要能再提醒
        self._variant_hinted = False
        self._last_unpaired = False
        self._gate_note = ""               # 已连上 → 下次再进守卫要能重新提示
        self.connected = True
        self.note = i18n.L("已就绪（按了没反应？见日志里的恢复办法）",
                           "Ready (no response? see the log for recovery steps)")
        self._emit("status", {"connected": True, "note": self.note})
        if self.sink:
            self.sink.reset()

        loop = asyncio.get_running_loop()
        last_frame = [0.0]
        self._awake_at = time.time()        # 本次会话建立时刻（静默看门狗用）
        self._ctrl_seen = 0
        # 探活心跳的计数每段会话都要清零：它统计的是"这次 GET_CAPS 之后有没有
        # 收到 CAPS 应答"，跨会话累加会把新会话误判成"僵死"。
        self._caps_seen = 0
        self._sync_seen = 0
        self._caps_info = None
        # 本次连接以来成功过几次语音会话（"按键后备"判定用）
        self._sessions_at_connect = self.sessions
        self._reopen_at = 0.0
        self._reopen_requested = False

        def on_status(_c, data: bytearray):
            b = bytes(data)
            if not b:
                return
            loop.call_soon_threadsafe(self._on_status, b)

        def on_audio(_c, data: bytearray):
            self.frames += 1
            self._session_frames += 1
            last_frame[0] = time.time()
            if self.sink:
                try:
                    self.sink.feed_adpcm(bytes(data))
                except Exception:
                    pass

        def on_ctl(_c, data: bytearray):
            """控制特征（ab5e0002）的回话 —— 只有它支持 notify 时才会走到这里。

            ⚠ 真机实测这支 A3 的 `ab5e0002` 属性是 **`W`（只支持无响应写）**，
              既不能读也不能 notify —— 所以 GET_CAPS **没有回话**，别指望它。
              能力表只能从「按语音键后有没有 0x04」间接确认。
            """
            b = bytes(data)
            if not b:
                return
            self._ctrl_seen += 1
            loop.call_soon_threadsafe(self._log, f"语音：控制响应 {b.hex(' ')}")

        # ★ 服务表打一行：排查「连上了却没声音」时，第一件事是确认
        #   ab5e0002/3/4 在不在、属性对不对（W=无响应写，w=带响应写，n=notify）。
        self._log("语音：服务表 " + describe_services(client))

        # 控制通道：只有支持 notify/indicate 才订阅（本机这支不支持，订阅会直接报错）
        ctl_props = list(getattr(ctl, "properties", []) or [])
        ctl_notify = False
        if ctl is not None and ("notify" in ctl_props or "indicate" in ctl_props):
            try:
                await client.start_notify(ctl, on_ctl)
                ctl_notify = True
            except Exception as e:
                self._log(f"语音：控制特征订阅不上（{type(e).__name__}: {e}）")
        # 音频订阅必须先于状态订阅，避免丢掉起始帧
        await client.start_notify(audio, on_audio)
        await client.start_notify(status, on_status)

        # ★ 全通道监听：把这支遥控器**所有**能 notify/indicate 的特征都订上
        #   （ATVV 那三条除外），每条只记前 5 条。
        #   排查「按语音键却什么都收不到」时，这一层回答一个关键问题：
        #   **遥控器到底有没有发东西？发在哪个通道上？** 没有这一层，只能在
        #   "是不是订阅错了"里打转。
        for _s in client.services:
            for _c in _s.characteristics:
                _props = list(getattr(_c, "properties", []) or [])
                if not ("notify" in _props or "indicate" in _props):
                    continue
                if _c is audio or _c is status or _c is ctl:
                    continue
                self._watch_extra(client, _c)

        # 探针一：读一次电量。能读出来就证明这条链路是**双向通的** ——
        # 「连上了却没声音」时，先排除"其实链路是死的"这一种。
        self._log("语音：链路自检 —— " + await self._probe_link(client))

        if ctl:
            # ★ 写方式必须跟特征属性一致：ab5e0002 只有 W（无响应写）。
            #   对 W-only 特征用 response=True，Windows 可能在 ATT 层丢弃，
            #   而 API 不报错 —— 日志显示"已写入"，遥控器其实什么都没收到。
            use_resp = "write" in ctl_props and "write-without-response" not in ctl_props
            self._ctl_resp = use_resp
            # ★ 默认**不发** GET_CAPS（2026-10-27）。
            #   参考实现建链时发一次、然后等 3 秒要应答 —— 本机这台固件**从不回**
            #   （14:16 / 14:21 / 14:31 三次建链实测都没有 0x0B）。既然对空气喊话，
            #   唯一的价值只剩"万一它把遥控器搞晕"这个副作用 —— 那是净亏。
            #   想试的话把 config.json 的 voice.send_caps 设成 true。
            _want_caps = bool((self.voice_spec or {}).get("send_caps"))
            if not _want_caps:
                self._log("语音：跳过 GET_CAPS（这台固件不支持能力协商；"
                          "需要时可在 config.json 里设 voice.send_caps = true）")
            else:
                try:
                    await client.write_gatt_char(ctl, CAPS_CMD, response=use_resp)
                    self._caps_at = time.time()
                    # ★ 只报"已写入"会骗人：写操作成功只代表 ATT 层没报错。真正算数的
                    #   是 3 秒内有没有 CAPS 应答（见 _caps_keepalive 里的探活）。
                    self._log("语音：已发 GET_CAPS（v1.0 六字节，" + CAPS_CMD.hex(" ")
                              + "）—— 等遥控器回能力应答（0x0B）")
                    if not ctl_notify:
                        self._log("语音：⚠ 控制通道不能收通知 —— 收不到能力应答，"
                                  "探活心跳会一直判失败；这条链多半不是系统 HID 那条")
                except Exception as e:
                    self._log(f"语音：GET_CAPS 写入失败 {type(e).__name__}: {e}")
        # 补发 GET_CAPS 要用到这两样（见 _rearm_caps）
        self._ctl = ctl
        self._last_press_frames = None

        how = "按一下" if self.voice.mode == "tap" else "按住"
        if self.voice.ok:
            self._log(f"语音：语音键目标 = {how} {self.voice.label}")
        else:
            self._log(f"语音：✗ 认不出语音键目标 {self.voice_spec} —— 语音键不会发任何键")
        self._log("语音：就绪 —— 按住遥控器【语音键】说话，松开即停")
        silent = asyncio.ensure_future(self._silent_watch(self.sessions))
        keepalive = asyncio.ensure_future(self._caps_keepalive(last_frame))

        disc = asyncio.Event()

        def on_disc(_c):
            loop.call_soon_threadsafe(disc.set)

        try:
            client._backend._disconnected_callback = on_disc      # 兜底
        except Exception:
            pass

        # 用轮询 + 断线事件维持会话：任何一边退出就结束本次会话
        try:
            while not self.stop_flag.is_set():
                if not client.is_connected:
                    self._log("语音：连接已断开")
                    break
                if getattr(self, "_reopen_requested", False):
                    # 有人要求重开语音会话：不靠 disconnect() 的回调（Windows 上
                    # 它可能挂住），会话自己在这儿收尾，交给外层重新建链。
                    self._reopen_requested = False
                    self._log("语音：按要求重开语音会话（先 MIC_CLOSE 再断链）")
                    break
                await asyncio.sleep(0.5)
        finally:
            self.connected = False
            self.note = i18n.L("已断开", "Disconnected")
            self.voice.release()
            silent.cancel()
            keepalive.cancel()
            await self._close_current()

    async def _caps_keepalive(self, last_frame, every=20.0, idle=20.0):
        """空闲看门狗：**不再周期性发 GET_CAPS**。

        为什么彻底去掉（2026-10-27，依据是另一个成熟实现 + 本机实测）：

          · 参考实现（remotemic-src/RC003）只在**会话建立时发一次** GET_CAPS，
            从来不周期性发。我们以前每 20 秒发一次。
          · 本机实测：**这台固件根本不回答 GET_CAPS**（14:16、14:21 两次建链，
            连发几次都没有 0x0B 应答）。也就是说这个周期纯属"对空气喊话"。
          · 更关键：以前那个周期发的是**畸形报文** `0A 00 04 00 01`（5 字节，
            v1.0 要求 6 字节）。真机两次"语音莫名其妙全死"（13:12、13:34）都紧
            跟在一次畸形保活之后 —— **有可能就是我们自己把遥控器搞晕的**。
            现在命令字节已改成正确的 6 字节，但既然它不支持 CAPS，就没必要再喊。

        现在这个协程只做一件事：**长时间没声音时**，把"可能僵死了、怎么恢复"
        这条提示说清楚（每 5 分钟最多一条，别刷屏）。
        """
        last_hint = 0.0
        last_probe = 0.0
        while not self.stop_flag.is_set() and self.connected:
            await asyncio.sleep(5.0)
            if not self.connected:
                break
            now = time.time()
            if now - last_frame[0] < idle:
                continue
            if now - last_hint < 300.0:
                continue
            # ★ 定时"重新开麦"探测（每 20 秒一次，和提示节流无关）：这是让「误按静音键」自动恢复的关键。
            #   静音键在这支原厂遥控器上**不上链路**（ETW 全链路抓包证实），我们
            #   看不到它；但实测它会让遥控器把 ATVV 录音通道挂起 —— 之后它连
            #   0x04 都不发，语音就再也起不来。
            #   而"MIC_OPEN"（遥控器本来就认的命令，参考实现按下语音键时就发它）
            #   能把它重新打开 —— 实测 15:41:10 主动开麦之后，15:41:18 的语音
            #   就正常了（47 帧）。
            #   问题是"语音键本身不上 HID"，所以用户只按语音键时我们毫无察觉。
            #   那就定时自己开一次：静音之后最多 ~20 秒，下一次按语音键就有声音。
            #   开完 1.5 秒没人说话就收回去，不留麦开着。
            if now - last_probe >= 20.0:
                last_probe = now
                self._try_open_mic(quiet=True)
            if now - last_hint >= 300.0:
                last_hint = now
                self._log(i18n.L(
                "语音：空闲中（不再发 GET_CAPS —— 这台固件不支持能力协商，"
                "再喊也没用，而且历史上正是它把遥控器搞晕过）。"
                "若按语音键没反应，多半是误按静音键把录音通道挂死了 —— "
                "**取电池 10 秒**能解（软件侧已实测救不回来）。",
                "Voice: idle (no more GET_CAPS — this firmware does not support "
                "capability negotiation, and it is exactly what used to wedge the "
                "remote). The mic is re-opened automatically every 20 s, which undoes "
                "the hang caused by pressing the mute key; if the voice key still does "
                "nothing, use “Repair voice” or pull the battery for 10 s."))

    async def _silent_watch(self, sessions0, wait=20.0):
        """连上 wait 秒还没收到任何语音数据 → 提示一句，但别把人吓着。

        为什么值得一条专门的日志：「连上了、就绪了、按语音键却没反应」是最难查的
        一种 —— 链路、服务、订阅都正常，就是没声音。把它和"链路是死的"分开说，
        排查时能少走一大圈（真机上一次就卡在这里）。

        ⚠ 措辞刻意保持中性：会话是长连接，用户连上后没马上按语音键是**完全正常**的，
        这条不该读起来像报错。
        """
        await asyncio.sleep(wait)
        if self.stop_flag.is_set() or not self.connected:
            return
        if self.sessions != sessions0:
            return
        self._log(f"语音：已连接 {wait:.0f} 秒，还没收到语音数据"
                  f"（控制响应 {self._ctrl_seen} 条）—— 按一下语音键试试；"
                  f"按了也没反应的话，先看上面「链路自检」那行能不能读出电量")

        # ★ 第二级（3 分钟）：这时候基本可以确定是遥控器僵死了，给一条**真正能解决
        #   问题**的建议，而不是继续让他对着"一切正常"的日志发呆。
        #   真机实证（2026-10-27 13:36~13:46）：按过静音键之后，链路 10 个服务全在、
        #   电量读得出、GET_CAPS 写入无报错，但遥控器连 0x04 都不发；完整重连、
        #   MIC_CLOSE(0d)、MIC_OPEN(0c)、GET_CAPS(0a) 全部无效 —— 只能取电池。
        await asyncio.sleep(160.0)
        if self.stop_flag.is_set() or not self.connected:
            return
        if self.sessions != sessions0:
            return
        self._log(i18n.L(
            "语音：链路正常，但 3 分钟里一条 ATVV 报文都没有 —— 遥控器的录音通道"
            "僵死了。**如果是按过静音键造成的，软件侧救不回来**（2026-10-27 实测："
            "MIC_OPEN / MIC_CLOSE / 全新 GATT 会话，规范拆链后重建，四种手段全部无效）。"
            "恢复办法（实测有效，顺序别变）：**取出电池 → 点「一键重配遥控器」删设备 → "
            "装回电池重新配对**。⚠ 只取电池装回不够（会变成已配对却连不上）。"
            "⚠ 别再按静音 / 音量 / 电源 / 输入源了 —— 这四个键在这支遥控器上"
            "**一按就把语音挂死**（2026-10-27 18:15 实测：语音连续 10 次会话正常，"
            "按一下静音立刻全废）。恢复出厂设置也改不了这个行为。",
            "Voice: the link is healthy, yet there has been no ATVV traffic for 3 "
            "minutes — the remote's recording channel is wedged. **If the mute key "
            "caused it, nothing on the software side recovers it** (measured "
            "2026-10-27: MIC_OPEN / MIC_CLOSE / a fresh GATT session with a proper "
            "teardown — all four failed). Recover by **pulling the battery for 10 s** "
            "(the remote reboots and its state machine resets; the pairing survives). "
            "If that does not help, re-pair the device. Do not press the mute key "
            "again — on this genuine A3 it goes over IR (it is meant for the TV), so "
            "it does nothing for the PC but kills the voice channel. "
            "machine, a battery pull alone leaves Windows' HID sub-devices as phantom "
            "nodes: Bluetooth then shows “paired but not connected” and you end up having "
            "to re-pair anyway."))
        self.note = i18n.L("按语音键没反应？取电池 10 秒即可",
                           "Voice key not responding? Pull the battery for 10 s")
        self._emit("status", {"connected": True, "note": self.note})

    # ---------- 语音键事件 ----------
    async def _probe_link(self, client):
        """读几个只读特征，证明这条链路**双向通**。

        为什么值得：「连上了、订阅也成功、按语音键却一声不响」时，最怕的其实是
        链路早就半死 —— Windows 的 GATT 会话可以停在"看起来已连接"的样子。
        能读出电量，就说明 ATT 层来去都通，问题只在遥控器自己不发 ATVV 事件
        （那就是固件状态的事，取电池 10 秒）。
        """
        def find(prefix):
            for s in client.services:
                for c in s.characteristics:
                    if str(c.uuid).lower().startswith(prefix):
                        return c
            return None

        bits = []
        for prefix, label in (("00002a19", "电量"), ("00002a26", "固件"),
                              ("00002a24", "型号"), ("00002a29", "厂商")):
            ch = find(prefix)
            if ch is None:
                continue
            try:
                raw = bytes(await client.read_gatt_char(ch))
            except Exception as e:
                bits.append(f"{label}读不到({type(e).__name__})")
                continue
            if prefix == "00002a19" and raw:
                bits.append(f"电量 {raw[0]}%")
            else:
                bits.append(f"{label}=" + raw.decode("utf-8", "replace").strip("\x00")[:24])
        return "，".join(bits) if bits else "读不到任何只读特征（链路可能半死）"

    def _rearm_caps(self, delays=(0.0, 0.30), min_gap=1.0, reason="starved"):
        """补发 GET_CAPS —— 让遥控器重新进录音态。

        为什么需要：GET_CAPS 只在**建链时**发一次，而遥控器会在两次按语音键之间
        自己休眠。醒来后它照样发 0x04（"我按下了"），却一帧音频都不送 ——
        日志就是「本段 0~5 帧」，听感是"按了语音键但没声音、输入法不出字"，
        很容易被误判成"语音键坏了"。

        真机上 0x04 到达时补发一次就能恢复，但偶尔要再来一次，所以发两遍
        （立刻 + 0.3 秒后），两遍都是写特征、开销可以忽略。
        """
        ctl = getattr(self, "_ctl", None)
        loop = getattr(self, "_loop", None)
        client = self._client
        if ctl is None or loop is None or client is None:
            return
        if time.time() - getattr(self, "_caps_at", 0.0) < min_gap:
            return                        # 刚发过，别重复刷
        self._caps_at = time.time()

        async def _do():
            for i, d in enumerate(delays):
                if d:
                    await asyncio.sleep(d)
                if not client.is_connected:
                    return
                try:
                    await client.write_gatt_char(
                        ctl, CAPS_CMD, response=bool(getattr(self, "_ctl_resp", False)))
                    if i == 0 and reason == "manual":
                        self._log("语音：手动补发 GET_CAPS（重新激活录音态）")
                    elif i == 0 and reason == "starved":
                        self._log("语音：上一段没收到音频 —— 补发 GET_CAPS"
                                  "（让遥控器重新进录音态）")
                except Exception as e:
                    self._log(f"语音：补发 GET_CAPS 失败 {type(e).__name__}: {e}")
                    return

        try:
            loop.call_soon_threadsafe(lambda: asyncio.ensure_future(_do()))
        except Exception:
            pass

    def _on_status(self, b: bytes):
        active = getattr(self, "_active", False)
        op = b[0]

        # ── 0x0B：能力应答（CAPS）──────────────────────────────────────
        # 这是整条链路上**唯一**"你问它就必须答"的东西，所以它是探活心跳：
        # 收到它就证明遥控器的 ATVV 栈活着；连续几轮问不到，就是僵死了。
        # 格式（v1.0，9 字节）：0B 01 00 <codecs> <interaction> <frame_size:2> …
        if op == OP_CAPS:
            self._caps_miss = 0
            self._caps_supported = True     # 答过一次 = 这个固件支持能力协商
            self._caps_seen = getattr(self, "_caps_seen", 0) + 1
            self._caps_at = time.time()
            try:
                ver = (b[1] << 8) | b[2]
                codecs = b[3] if len(b) > 3 else 0
                inter = b[4] if len(b) > 4 else 0
                frame = ((b[5] << 8) | b[6]) if len(b) > 6 else 0
                self._caps_info = (ver, codecs, inter, frame)
                if self._caps_seen == 1:
                    codec_txt = {0x01: "8kHz PCM", 0x02: "16kHz ADPCM"}.get(
                        codecs & 0x03, f"0x{codecs:02x}")
                    self._log(f"语音：能力协商成功 —— 协议 v{ver >> 8}.{ver & 0xFF}，"
                              f"编码 {codec_txt}，交互 0x{inter:02x}，帧长 {frame}")
            except Exception:
                if self._caps_seen == 1:
                    self._log(f"语音：收到能力应答 {b.hex()}（解析失败，但心跳是通的）")
            return

        # ── 0x08：遥控器报告"麦克风按键"状态 ────────────────────────────
        if op == OP_MIC_BUTTON:
            self._log(f"语音：遥控器报告麦克风按键 {b.hex()}")
            return

        # ── 0x0A：音频同步包（正常现象，不该刷屏）──────────────────────
        if op == OP_AUDIO_SYNC:
            n = getattr(self, "_sync_seen", 0) + 1
            self._sync_seen = n
            if n <= 3:
                self._log(f"语音：音频同步包 {b.hex()}（第 {n} 条，正常）")
            return

        # ★ 0x04 帧的第 4 字节是会话号（`04 <reason> <codec> <sid>`，见
        #   atvv_session.py 第 209 行）。后面 MIC_CLOSE 和保活都要带它。
        if op == 0x04 and len(b) >= 4:
            self._last_session_id = b[3]

        # ── 0x04 重新进入（处于"被固件 20 秒硬掐后自动续录"态时）─────────────
        #   自动续录把 IME 热键一直按着；万一用户在固件某次掐断后真的又按了一下语音键，
        #   这里先把上一轮还按着的 IME 热键和会话清干净，再当一次全新按下处理，
        #   避免"叠两层按下"或卡在续录态出不去。
        if op == 0x04 and active and getattr(self, "_voice_reheld", False):
            try:
                self.voice.release()
            except Exception:
                pass
            try:
                self.atvv_cmd(self._mic_close_cmd())
            except Exception:
                pass
            self._active = False
            self._voice_reheld = False
            self._voice_held = False
            active = False

        if op == 0x04 and not active:
            # 上一段"按了却没音频" → 这次按下时先把录音态补回来（见 _rearm_caps）
            prev = getattr(self, "_last_press_frames", None)
            if prev is not None and prev < 20:
                self._rearm_caps()
            # ★ 对齐参考实现（remotemic-src/RC003 的 ble_transport_winrt.py）：
            #   主机在"按下语音键"时显式发 MIC_OPEN（0C 00），"松开"时发 MIC_CLOSE。
            #   我们以前从不发 —— 全靠遥控器自己发 0x04 来开麦，主机这边是"哑"的"。
            #   这是与成熟实现最大的一个行为差异，补上。
            self.atvv_cmd(MIC_OPEN_CMD)
            self._active = True
            self._start_extend_keepalive()
            self.sessions += 1
            self._session_frames = 0
            self._voice_held = True
            self._voice_reheld = False
            self._press_time = time.time()
            self._emit("key", {"id": "voice", "down": True})
            self._log(f"语音：▼ 开始（第 {self.sessions} 次会话）")
            if self.voice.mode == "tap":
                self.voice.tap()
            else:
                self.voice.press()
        elif b[0] == 0x00 and active:
            now = time.time()
            elapsed = now - getattr(self, "_press_time", 0.0)
            # ★ 固件在 ~20 秒强行掐断（本机 A3 不送音频、只认 0E 续命，且老节奏把保活
            #   卡在死线上）：这是"假结束"。只要距按下约 20 秒、且还没续录过，就自动
            #   重开会话并继续按住 IME —— 多数情况下配合修正后的保活节奏能续住；即便
            #   固件仍硬掐，这次重开也只再续 ~20 秒，下一轮 0x00 会走到正常释放，不会卡死。
            #   用 18~23 秒这个窄窗口区分"固件掐断"和"用户真的松手"（用户极少恰好
            #   在 20 秒整松手），避免把一次正常短按误判成掐断而卡住输入法。
            premature = (getattr(self, "_voice_held", False)
                         and not getattr(self, "_voice_reheld", False)
                         and 18.0 <= elapsed <= 23.0)
            if premature:
                self._voice_reheld = True
                self._press_time = now
                try:
                    self.atvv_cmd(MIC_OPEN_CMD)
                except Exception:
                    pass
                self._log("语音：⚠ 会话约 20 秒被固件掐断（A3 固件不送音频、只认 0E 续命）"
                          "—— 已自动重开并继续录音；若你已松开语音键，请再按一下让它彻底结束")
                return
            self._active = False
            self._emit("key", {"id": "voice", "down": False})
            self.voice.release()
            self._voice_held = False
            self._voice_reheld = False
            n = self._session_frames
            self._last_press_frames = n
            # ★ 松开时显式关麦（同样对齐参考实现），下一段按下前状态是干净的。
            self.atvv_cmd(self._mic_close_cmd())
            self._log(f"语音：▲ 结束（本段 {n} 帧音频 ≈ {n / 62.5:.1f}s）")
            if n < 20:
                # 按键通了、但遥控器没送音频 —— 这是另一类问题（没真正进录音态），
                # 跟「语音键读不到」完全不是一回事，日志里必须分开说。
                self._log("语音：⚠ 音频帧太少 —— 遥控器没在送音频（多半没真正进录音态）")
            elif self.sink is None:
                self._log("语音：⚠ 音频出口还没就绪，这段没送出去（看护任务正在重试）")
        elif b[0] not in (0x00,):
            # 既不是"开始说话"(0x04) 也不是"结束"(0x00)：把原始字节打出来。
            # 遥控器换过固件/重新配对之后，通知里的操作码**有可能不一样** ——
            # 以前这种情况会被静默丢掉，表现就是"按语音键日志一行都没有"，
            # 让排查变成瞎猜。这里留一行原始帧，一眼就能看出它到底发了什么。
            self._log(f"语音：未识别的状态帧 {b.hex()}（首字节 0x{b[0]:02x}）")

    def stop(self):
        self.stop_flag.set()
        self.voice.release()
