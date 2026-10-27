# -*- coding: utf-8 -*-
"""验证语音键「按住<20 秒被掐」的根因修复。

根因：ATVV 会话寿命约 20 秒，主机必须持续发 `0E <sid>` 续命。参考实现靠遥控器
持续送音频把固件计时器喂着，所以在 20 秒处续命能成功；本机 Google A3 不送音频，
只能靠 `0E` 续，而旧代码先 `sleep(20)` 再发第一次（还"先睡后判 _active"），
第一次续命正好卡在死线上、甚至根本来不及发 —— 于是会话必然在 20 秒被掐，
表现就是"按住语音键不到 20 秒输入法就停"。

本测试不依赖真机/蓝牙，只验证两件事：
  1) 保活第一次发送在 8 秒（远早于 20 秒死线），且内容是 `0E <sid>`；
  2) 固件在 ~20 秒发来的"假结束" `0x00` 会被自动重开续录（IME 不中断），
     且不会误把一次正常的短按当成掐断。

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


def test_premature_close_auto_reopen():
    """固件在 ~20 秒发的'假结束'应自动重开续录，且不释放 IME。"""
    sent = []
    vr = voice.VoiceRole(on_event=lambda *a, **k: None)
    vr._active = True
    vr._voice_held = True
    vr._voice_reheld = False
    vr._press_time = time.time() - 20.0   # 距按下约 20 秒 → 命中固件掐断窗口
    vr._last_session_id = 7
    vr.atvv_cmd = lambda p: sent.append(bytes(p))
    vr._on_status(bytes([0x00]))
    assert vr._voice_reheld is True, "应标记为已续录"
    assert vr._active is True, "续录期间 IME 应保持按下（_active 不置否）"
    assert any(s[:1] == b"\x0c" for s in sent), (
        f"应发送 MIC_OPEN 重开会话，实际 {[x.hex() for x in sent]}")
    PASS.append("20 秒固件掐断被自动重开续录（IME 不中断）")


def test_genuine_short_release_is_not_premature():
    """用户真的在 5 秒松手：不应误判成掐断，应正常释放 IME。"""
    vr = voice.VoiceRole(on_event=lambda *a, **k: None)
    vr._active = True
    vr._voice_held = True
    vr._voice_reheld = False
    vr._press_time = time.time() - 5.0    # 只按了 5 秒就松手 → 不是 20 秒掐断
    vr._last_session_id = 9
    released = []
    vr.voice.ok = True
    vr.voice.down = True
    vr.voice.release = lambda: released.append(True)
    vr._on_status(bytes([0x00]))
    assert vr._voice_reheld is False, "短按松手不应被当成 20 秒掐断"
    assert vr._active is False, "短按松手应正常结束会话"
    assert released, "短按松手应释放 IME 热键"
    PASS.append("正常短按松手被正确识别为结束（不误判为掐断）")


if __name__ == "__main__":
    test_keepalive_first_send_before_20s()
    test_premature_close_auto_reopen()
    test_genuine_short_release_is_not_premature()
    print("全部通过：")
    for p in PASS:
        print("  [OK]", p)
