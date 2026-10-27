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
    """按了一下键 → 立刻放行。"""
    v = new_role(True)
    t0 = time.time()
    threading.Timer(0.3, v.poke).start()
    await asyncio.wait_for(v._wait_hid_awake(), timeout=3.0)
    dt = time.time() - t0
    print(f"  [OK] 按键后 {dt:.2f}s 放行（应 ≈0.3s）")
    assert 0.2 < dt < 1.0, dt


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
        ("HID 在 + 刚按键 → 放行", t_pass_after_poke),
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
