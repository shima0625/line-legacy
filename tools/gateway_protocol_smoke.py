#!/usr/bin/env python3
"""Small protocol checks for locally synthesized legacy RPCs."""

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import legy_proxy as gateway  # noqa: E402


def check_sync_channel_data():
    request = bytes.fromhex(
        "8221000f73796e634368616e6e656c44617461260018056a615f4a5000"
    )
    reply = gateway.synth_for_method("syncChannelData", 0, request)
    seqid, pos = gateway.uvarint(reply, 2)
    name_size, pos = gateway.uvarint(reply, pos)
    result, end = gateway._tc_read_struct(reply, pos + name_size)
    data = result[0][1]

    assert seqid == 0 and end == len(reply)
    assert data[1] == (9, []) and data[2] == (9, [])
    assert data[3] == (6, 0)
    assert data[4][0] == 6 and data[4][1] > int(time.time() * 1000)

    os.environ["FORWARD_METHODS"] = "syncChannelData"
    assert not gateway._should_forward("syncChannelData")


if __name__ == "__main__":
    check_sync_channel_data()
    print("gateway protocol smoke checks passed")
