# -*- coding: utf-8 -*-
"""验证语音键「按住<20 秒被掐」的根因修复（第二版：按关闭帧 reason 区分）。

根因：ATVV 会话寿命约 20 秒，且本机 A3 不送音频、只认主机 `0E <sid>` 续命（还不一定认）。
但关键认知是：输入法能否持续录音，取决于 **IME 热键是否被本地按着**，与 ATVV 会话是否
活着无关 —— 会话只是"按下/松开"的信号。所以：
  - 关闭帧 `00 <reason>` 里 reason==2 = 用户物理松手 → 真正释放 IME；
  - reason≠2（设备超时/掐断）→ **绝不松开 IME**，只重开会话等"真松手"的 0x00。
这样录音能跨过 20 秒死线连续进行；就算固件硬卡 ~20 秒，最坏也只是 ~40 秒一段，不会卡死。

本测试不依赖真机/蓝牙，只验证两件事：
  1) 保活第一次发送在 8 秒（远早于 20 秒死线），且内容是 `0E <sid>`；
  2) 按 reason 字节正确区分"真松手(reason==2)"与"固件掐断(reason≠2)"。

用法（仓库根目录）：
    python tests/test_keepalive.py
"""
import os
import sys
import threading
import time
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import voice  # noqa: E402

PASS = []


def test_keepalive_first_send_before_20s():
    """保活必须在 20 秒死线之前就开始发续命包。"""
    sent = []
    sleeps = []
    vr = voice.VoiceRole(on_event=lambda *a, **k: None)
    vr._last_session_id = 5
    vr.connected = True
    vr._active = True
    vr.stop_flag = threading.Event()
    vr.atvv_cmd = lambda p: sent.append(bytes(p))
    with mock.patch.object(voice.time, "sleep", lambda s: sleeps.append(s)):
        vr._start_extend_keepalive()
        for _ in range(300):          # 等线程跑完"第一次 sleep + 发送"
            if sent:
                break
            time.sleep(0.005)
    vr.stop_flag.set()
    assert sent, "保活线程未发送任何续命包"
    assert sent[0] == b"\x0e\x05", f"续命包应为 0E 05，实际 {sent[0].hex()}"
    assert sleeps and abs(sleeps[0] - 8.0) < 0.01, (
        f"第一次保活前等待应为 ~8s（修复前是 20s 卡死线），实际 {sleeps}")
    PASS.append("保活首次发送在 8s（远早于 20s 死线），内容 0E 05")


def test_timeout_close_keeps_recording():
    """固件在 ~20 秒发来的'假结束'(reason≠2) 应保持 IME 按下、继续录音并续会话。"""
    sent = []
    released = []
    vr = voice.VoiceRole(on_event=lambda *a, **k: None)
    vr._active = True
    vr._voice_held = True
    vr._voice_reheld = False
    vr._press_time = time.time() - 20.0
    vr._last_session_id = 7
    vr.atvv_cmd = lambda p: sent.append(bytes(p))
    vr.voice.ok = True
    vr.voice.down = True
    vr.voice.release = lambda: released.append(True)
    vr._on_status(bytes([0x00]))          # reason 缺省=0 → 设备超时/掐断
    assert vr._voice_reheld is True, "应进入续录态"
    assert vr._active is True, "续录期间 IME 应保持按下（_active 不置否）"
    assert not released, "固件掐断时绝不应释放 IME 热键"
    assert any(s[:1] == b"\x0c" for s in sent), (
        f"应发送 MIC_OPEN 重开会话，实际 {[x.hex() for x in sent]}")
    PASS.append("固件 20 秒掐断(reason≠2) → IME 继续录音并续会话（不释放）")


def test_genuine_release_reason2_ends():
    """关闭帧 reason==2（用户真松手）应立即释放 IME。"""
    released = []
    vr = voice.VoiceRole(on_event=lambda *a, **k: None)
    vr._active = True
    vr._voice_held = True
    vr._voice_reheld = False
    vr._press_time = time.time() - 5.0
    vr._last_session_id = 9
    vr.voice.ok = True
    vr.voice.down = True
    vr.voice.release = lambda: released.append(True)
    vr._on_status(bytes([0x00, 2]))       # reason==2 → 物理松手
    assert vr._voice_reheld is False, "真松手不应留在续录态"
    assert vr._active is False, "真松手应正常结束会话"
    assert released, "真松手应释放 IME 热键"
    PASS.append("关闭帧 reason==2（真松手）立即释放 IME")


def test_forced_then_second_close_releases():
    """续录态再遇一次关闭 → 视为真松手并释放（最坏 ~40 秒一段，不卡死）。"""
    released = []
    vr = voice.VoiceRole(on_event=lambda *a, **k: None)
    vr._active = True
    vr._voice_held = True
    vr._voice_reheld = True              # 已在续录态
    vr._press_time = time.time() - 40.0
    vr._last_session_id = 11
    vr.voice.ok = True
    vr.voice.down = True
    vr.voice.release = lambda: released.append(True)
    vr._on_status(bytes([0x00]))          # 第二次关闭
    assert vr._active is False, "续录态再遇关闭应结束会话"
    assert released, "续录态再遇关闭应释放 IME 热键"
    PASS.append("续录态再遇关闭 → 释放（不卡死）")


if __name__ == "__main__":
    test_keepalive_first_send_before_20s()
    test_timeout_close_keeps_recording()
    test_genuine_release_reason2_ends()
    test_forced_then_second_close_releases()
    print("全部通过：")
    for p in PASS:
        print("  [OK]", p)
