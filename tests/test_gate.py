# -*- coding: utf-8 -*-
"""验证「链路守卫」：系统 HID 握着链路时，语音只在刚有按键的窗口里建链。

这是本 fork 最关键的一处修复 —— 上游把启动顺序弄反了（语音先建链），语音
每 3 秒硬连一次，把系统 HID 挤掉，表现是「按语音键没反应」，接着连方向键也不动了。

用法（在仓库根目录）：
    python tests/test_gate.py

不需要遥控器、不需要蓝牙、不需要装 bleak —— 只测守卫的状态机。
"""
import asyncio
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import voice  # noqa: E402

LOGS = []


def new_role(hid_ok):
    v = voice.VoiceRole(
        lambda kind, payload=None: LOGS.append(payload) if kind == "log" else None)
    v.hid_probe = lambda: hid_ok
    return v


async def t_blocked_when_asleep():
    """HID 在、但遥控器没按过键 → 守卫必须一直等（不返回）。"""
    v = new_role(True)
    try:
        await asyncio.wait_for(v._wait_hid_awake(), timeout=1.5)
    except asyncio.TimeoutError:
        print("  [OK] 一直等着，没有去建链")
        return
    raise AssertionError("守卫放行了 —— 这正是把 HID 挤掉的路径")


async def t_pass_after_poke():
    """按了一下键 → 不是立刻放行，而是等加密链路握稳（HID_POST_KEY_SETTLE_S）再放行。

    2026-10-27 真机血泪：按键后**立刻**建链会抢到一条未加密的新链，遥控器只给它
    5 个基础服务（连 1812 都没有），ATVV 整个消失。同一支遥控器只要晚十几秒连，
    拿到的就是完整 10 服务、语音连续 8 段全部成功。所以这里断言的是"等了"而不是
    "秒放"——守的是加密握手的时间窗。
    """
    v = new_role(True)
    t0 = time.time()
    threading.Timer(0.3, v.poke).start()
    await asyncio.wait_for(v._wait_hid_awake(), timeout=8.0)
    dt = time.time() - t0
    print(f"  [OK] 按键后 {dt:.2f}s 放行"
          f"（应 ≈0.3s + {voice.HID_POST_KEY_SETTLE_S:.1f}s 握手等待）")
    lo = 0.3 + voice.HID_POST_KEY_SETTLE_S - 0.3
    hi = 0.3 + voice.HID_POST_KEY_SETTLE_S + 1.5
    assert lo < dt < hi, f"实测 {dt:.2f}s 不在 {lo:.1f}~{hi:.1f}s 之间"


async def t_settle_has_cap():
    """用户连按方向键、活动时刻被不停刷新 → 也不能无限等（HID_SETTLE_CAP_S 上限）。"""
    v = new_role(True)
    stop = threading.Event()

    def spam():
        while not stop.is_set():
            v.poke()
            time.sleep(0.2)

    threading.Thread(target=spam, daemon=True).start()
    t0 = time.time()
    try:
        await asyncio.wait_for(v._wait_hid_awake(), timeout=12.0)
    finally:
        stop.set()
    dt = time.time() - t0
    print(f"  [OK] 连按不停时 {dt:.2f}s 后仍然放行（上限 "
          f"{voice.HID_SETTLE_CAP_S:.1f}s，不会被拖死）")
    assert dt < voice.HID_SETTLE_CAP_S + 2.5, dt


async def t_pass_when_no_hid():
    """HID 不在（设备不在 / 走 frida 旁路）→ 不需要等，直接放行。"""
    v = new_role(False)
    t0 = time.time()
    await asyncio.wait_for(v._wait_hid_awake(), timeout=1.0)
    print(f"  [OK] HID 不在，{time.time() - t0:.2f}s 直接放行")


async def t_window_expires():
    """按过键但已过去很久（遥控器又睡了）→ 继续等，不能硬连。"""
    v = new_role(True)
    v.poke()
    v._activity_at = time.time() - (voice.HID_AWAKE_WINDOW_S + 5)
    try:
        await asyncio.wait_for(v._wait_hid_awake(), timeout=1.2)
    except asyncio.TimeoutError:
        print(f"  [OK] 超出 {voice.HID_AWAKE_WINDOW_S:.0f}s 窗口后重新等按键")
        return
    raise AssertionError("过期窗口仍然放行")


async def t_blocked_while_reconnecting():
    """HID 正在重建（刚换电池/重新配对）→ 一步都不许动，哪怕刚按过键。

    这一条对应真机上「蓝牙里看着连上了、马上又断」：那段时间 Windows 在重建
    HID 子设备，语音插进去建链会把重建无限拉长。
    """
    v = new_role("reconnecting")
    v.poke()                                  # 刚按过键，窗口是开的
    try:
        await asyncio.wait_for(v._wait_hid_awake(), timeout=1.5)
    except asyncio.TimeoutError:
        assert v._activity_at == 0.0, "重建期间必须把按键窗口作废"
        print("  [OK] 重建期间一步都不动，且按键窗口已作废")
        return
    raise AssertionError("重建期间放行了 —— 会把 Windows 的 HID 重建搅乱")


async def main():
    tests = [
        ("HID 在 + 没按键 → 死等", t_blocked_when_asleep),
        ("HID 正在重建 → 死等", t_blocked_while_reconnecting),
        ("HID 在 + 刚按键 → 等握手再放行", t_pass_after_poke),
        ("连按不停 → 握手等待有上限", t_settle_has_cap),
        ("HID 不在 → 不拦", t_pass_when_no_hid),
        ("窗口过期 → 重新等", t_window_expires),
    ]
    for name, fn in tests:
        print(f"[{name}]")
        await fn()
    print("\n全部通过。日志如下：")
    for line in LOGS[:6]:
        print("   ", line)


if __name__ == "__main__":
    asyncio.run(main())
