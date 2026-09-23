import json

from sentinel.audit import AuditLog


def _log(tmp_path, n=3, key="k"):
    log = AuditLog(tmp_path / "a.jsonl", key=key, warn_unsigned=False)
    for i in range(n):
        log.append("decision", {"i": i})
    return log


def test_chain_verifies(tmp_path):
    log = _log(tmp_path, 5)
    ok, msg = log.verify()
    assert ok and "5 records" in msg


def test_tamper_detected(tmp_path):
    log = _log(tmp_path)
    p = log.path
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1]); rec["payload"]["i"] = 99; lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    ok, msg = log.verify()
    assert not ok and "record 2" in msg


def test_forged_append_without_key_detected(tmp_path):
    log = _log(tmp_path, 1)
    AuditLog(log.path, key="wrong", warn_unsigned=False).append("decision", {"i": 1})
    ok, msg = log.verify()
    assert not ok and "signature" in msg


def test_drop_last_record_detected(tmp_path):
    log = _log(tmp_path, 3)
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:2]) + "\n")
    ok, msg = log.verify()
    assert not ok and "truncated" in msg


def test_truncate_to_zero_detected(tmp_path):
    log = _log(tmp_path, 3)
    log.path.write_text("")
    ok, msg = log.verify()
    assert not ok and "truncated" in msg


def test_delete_log_but_head_survives_detected(tmp_path):
    log = _log(tmp_path, 3)
    log.path.unlink()
    ok, _ = log.verify()
    assert not ok


def test_head_missing_detected(tmp_path):
    log = _log(tmp_path, 3)
    log.head_path.unlink()
    ok, msg = log.verify()
    assert not ok and "head" in msg


def test_unparseable_line_flagged_and_append_continues(tmp_path):
    log = _log(tmp_path, 2)
    with log.path.open("a") as f:
        f.write("garbage line\n")
    ok, msg = log.verify()
    assert not ok and "unparseable" in msg
    log.append("decision", {"i": 9})  # must not raise
    recs = [r for r in log.records() if "_unparseable" not in r]
    assert recs[-1]["seq"] == 3


def test_reorder_detected(tmp_path):
    log = _log(tmp_path, 3)
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join([lines[0], lines[2], lines[1]]) + "\n")
    ok, _ = log.verify()
    assert not ok


def test_independently_retained_checkpoint_detects_complete_local_deletion(tmp_path):
    log = _log(tmp_path)
    anchor = log.checkpoint()
    log.append("decision", {"i": 4})
    assert log.verify(checkpoint=anchor)[0]  # A checkpoint anchors a prefix, not a frozen log.
    log.path.unlink()
    log.head_path.unlink()
    assert not log.verify(checkpoint=anchor)[0]
    # Even a replacement chain signed using the original key cannot match the anchor.
    log.append("decision", {"replacement": True})
    assert not log.verify(checkpoint=anchor)[0]
