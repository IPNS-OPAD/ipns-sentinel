import os
import sys

import pytest

from sentinel.adapters.claude_stream import StreamSession, StreamFailure


def test_multiple_user_turns_share_one_live_process_and_conversation(tmp_path):
    fixture = """import json,sys
print(json.dumps({'type':'system','subtype':'init','session_id':'one','tools':['mcp__sentinel__run_python']}),flush=True)
count=0
for line in sys.stdin:
    message=json.loads(line)
    count+=1
    print(json.dumps({'type':'result','subtype':'success','session_id':'one','count':count,
                      'text':message['message']['content']}),flush=True)
"""
    with StreamSession([sys.executable, "-u", "-c", fixture], cwd=tmp_path, env=dict(os.environ)) as session:
        pid = session.pid
        first = session.turn("first", timeout_s=2)
        second = session.turn("second", timeout_s=2)
        assert first[-1]["count"] == 1 and second[-1]["count"] == 2
        assert first[-1]["session_id"] == second[-1]["session_id"] == "one"
        assert session.pid == pid and second[-1]["text"] == "second"
    assert session.returncode is not None


@pytest.mark.parametrize("fixture", ["import time; time.sleep(30)",
    "print('not-json',flush=True)", "print('x'*3000,flush=True)"])
def test_bad_or_unresponsive_stream_is_bounded_and_not_retried(tmp_path, fixture):
    with StreamSession([sys.executable, "-u", "-c", fixture], cwd=tmp_path, env=dict(os.environ), max_output_bytes=1024) as session:
        with pytest.raises(StreamFailure):
            session.turn("one", timeout_s=0.1)
        with pytest.raises(StreamFailure):
            session.turn("do not retry", timeout_s=0.1)
    assert session.returncode is not None and len(session.stdout) <= 1024
