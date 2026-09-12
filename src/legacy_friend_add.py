"""Translate an explicit legacy QR friend-add, never replay recorded writes."""
import hashlib
import http.client
import json
import os
import re
import ssl
import threading
import time

_lock = threading.RLock()
_tickets = {}
_added = {}


def remove_recommendation(g, mid):
    """A successful friend-add consumes the local recommendation snapshot."""
    target = mid.decode() if isinstance(mid, bytes) else str(mid)
    base = g['_ARTIFACTS']
    for filename, fallback in (('recommendation_mids.json', []),
                               ('recommendation_contacts.json', [])):
        path = os.path.join(base, filename)
        try:
            with open(path, encoding='utf-8') as source:
                values = json.load(source)
            if not isinstance(values, list):
                values = fallback
            if filename == 'recommendation_mids.json':
                values = [value for value in values if str(value) != target]
            else:
                values = [value for value in values
                          if not isinstance(value, dict) or str(value.get('mid', '')) != target]
            temp = path + '.tmp'
            with open(temp, 'w', encoding='utf-8') as output:
                json.dump(values, output, ensure_ascii=False)
            os.replace(temp, path)
        except (OSError, ValueError, TypeError):
            g['log']('[friend-add] recommendation snapshot update failed')


def rejection_diagnostic(result):
    """Keep only rejection code/hint locally, not requests, IDs or credentials."""
    value = result.get(1, (None, {}))
    if value[0] != 12:
        return
    hint = value[1].get(2, (8, b''))[1]
    if isinstance(hint, bytes):
        hint = hint.decode('utf-8', 'replace')
    if not isinstance(hint, str):
        hint = ''
    hint = re.sub(r'https?://\S+|[ucr][0-9a-f]{32}|[A-Za-z0-9_+/=-]{24,}', '[redacted]', hint[:1000])
    record = {'code': value[1].get(1, (None, None))[1], 'hint': hint}
    base = os.environ.get('ARTIFACTS_DIR') or os.environ.get('LINE_LEGACY_HOME') or os.path.dirname(__file__)
    path = os.path.join(base, 'friend_add_last_rejection.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(record, stream, ensure_ascii=False)


def fields(g, data):
    if data[:2] not in (b'\x82\x21', b'\x82\x41'):
        raise ValueError('Unexpected RPC envelope')
    _, i = g['uvarint'](data, 2)
    size, i = g['uvarint'](data, i)
    i += size
    values, end = g['_tc_read_struct'](data, i)
    if end != len(data):
        raise ValueError('Incomplete RPC envelope')
    raw, prev = {}, 0
    while data[i]:
        h = data[i]; i += 1
        typ, delta = h & 15, h >> 4
        if delta:
            fid = prev + delta
        else:
            zz, i = g['uvarint'](data, i)
            fid = (zz >> 1) ^ -(zz & 1)
        start = i
        _, i = g['_tc_read_value'](data, i, typ)
        raw[fid] = data[start:i]
        prev = fid
    return values, raw


def identity(token):
    return hashlib.sha256(token.encode()).digest()


def common_group(g, mid):
    joined, _ = g['_load_legacy_groups']()
    matches = []
    target = mid.decode() if isinstance(mid, bytes) else mid
    for gid, group in joined.items():
        members = group.get('members', [])
        if target in [m.get('mid') for m in members if isinstance(m, dict)]:
            matches.append(gid)
    return matches[0] if len(matches) == 1 else None


def remember(g, request, response, token):
    try:
        args, _ = fields(g, request)
        result, _ = fields(g, response)
        contact = result[0][1]
        mid = contact[1][1]
        ticket = args[2][1]
        if result[0][0] != 12 or not re.fullmatch(b'u[0-9a-f]{32}', mid):
            return
        with _lock:
            now = time.monotonic()
            for key in list(_tickets):
                if now - _tickets[key][0] > 600:
                    del _tickets[key]
            if len(_tickets) >= 256:
                _tickets.pop(next(iter(_tickets)))
            _tickets[(identity(token), mid)] = (now, ticket)
    except (KeyError, ValueError, TypeError, IndexError):
        pass


def rpc(g, token, method, path, args, seq):
    u = g['put_uvarint']
    body = b'\x82\x21' + u(seq) + u(len(method)) + method.encode() + args + b'\x00'
    # ★アプリ種別をハードコードしないこと。トークン・mid と揃っていないと
    #   approveChannelAndIssueChannelToken が拒否され、ホームとタイムラインが
    #   「接続できませんでした」になる(2026-09-12 に再発)。
    app = (g['bridge_app_string']() if 'bridge_app_string' in g
           else 'DESKTOPWIN\t9.8.0\tWINDOWS\t10.0.0-NT-x64')
    conn = http.client.HTTPSConnection('gd2.line.naver.jp', timeout=20,
                                       context=ssl.create_default_context())
    try:
        conn.request('POST', path, body, headers={
            'Content-Type': 'application/x-thrift', 'X-Line-Access': token,
            'X-Line-Application': app})
        response = conn.getresponse()
        data = response.read()
        if response.status != 200:
            raise ValueError('Upstream HTTP failure')
        return fields(g, data)
    finally:
        conn.close()


def handle(g, request, seq, token):
    u = g['put_uvarint']
    name = 'findAndAddContactsByMid'
    header = b'\x82\x41' + u(seq) + u(len(name)) + name.encode()
    def error(message):
        # Do not invent a quota or authentication error. Native application
        # exceptions use the generic failure path, distinct from TalkException.
        return g['build_app_exception'](name, seq, message, extype=6)
    try:
        args, _ = fields(g, request)
        reqseq = args[1][1]
        mid = args[2][1]
        if args[1][0] != 5 or args[2][0] != 8 or not re.fullmatch(b'u[0-9a-f]{32}', mid):
            return error('Invalid friend-add request')
        key = (identity(token), mid)
        with _lock:
            cached = _tickets.get(key)
            operation = (key, reqseq)
            # The modern account may already have this friend while the legacy
            # device has not synced it. Confirm real state before any write.
            current, current_raw = rpc(g, token, 'getContact', '/S4', g['_tc_str'](2, mid.decode()), seq)
            contact = current.get(0, (None, {}))
            if contact[0] != 12 or contact[1].get(1, (0, None))[1] != mid:
                return error('Unable to verify current friend state')
            if contact[1].get(11) == (5, 1):
                g['log']('[friend-add] already FRIEND upstream; returned legacy contact map without write')
                return header + b'\x0b\x00\x01\x8c' + u(len(mid)) + mid + current_raw[0] + b'\x00'
            if operation not in _added:
                inner = g['_tc_i32'](1, reqseq) + g['_tc_str'](1, mid.decode())
                if cached and time.monotonic() - cached[0] <= 600:
                    # QR provenance: AddMetaByUserTicket (union field 4).
                    ticket = cached[1]
                    tracking = (g['_tc_str'](1, '{"screen":"friendAdd:qrCode","spec":"native"}')
                                + b'\x1c\x4c' + g['_tc_str'](1, ticket.decode()) + b'\x00\x00\x00')
                    inner += b'\x1c' + tracking
                    g['log']('[friend-add] source=QR')
                else:
                    # Legacy RPC omits the source group. Infer it only when the
                    # current joined-group snapshot has one unambiguous match.
                    gid = common_group(g, mid)
                    if not gid:
                        return error('Unable to identify one source group for friend addition')
                    tracking = (g['_tc_str'](1, '{"screen":"groupMemberList","spec":"native"}')
                                + b'\x1c\x5c' + g['_tc_str'](1, gid) + b'\x00\x00\x00')
                    inner += b'\x1c' + tracking
                    g['log']('[friend-add] source=group member list (unique joined-group match)')
                inner += b'\x00'
                result, raw = rpc(g, token, 'addFriendByMid', '/RE4', b'\x1c' + inner, seq)
                if result.get(0, (None,))[0] != 12:
                    try:
                        rejection_diagnostic(result)
                    except OSError:
                        g['log']('[friend-add] diagnostic save failed')
                    g['log']('[friend-add] modern rejection fields=' + str(sorted(result)))
                    for fid, (typ, value) in result.items():
                        if typ == 12 and value.get(1, (None,))[0] == 5:
                            g['log']('[friend-add] rejection code=' + str(value[1][1]))
                    return error('The server rejected the friend-add request')
                _added[operation] = time.monotonic()
                if len(_added) > 256:
                    _added.pop(next(iter(_added)))
            # Modern success is empty; legacy needs map<MID, Contact>.
            result, raw = rpc(g, token, 'getContact', '/S4', g['_tc_str'](2, mid.decode()), seq)
            if result.get(0, (None,))[0] != 12 or result[0][1].get(1, (0, None))[1] != mid:
                return error('Friend added, but profile refresh failed')
            g['log']('[friend-add] modern success; legacy contact map returned')
            remove_recommendation(g, mid)
            return header + b'\x0b\x00\x01\x8c' + u(len(mid)) + mid + raw[0] + b'\x00'
    except (ValueError, KeyError, IndexError, TypeError, OSError):
        g['log']('[friend-add] request failed; no automatic retry')
        return error('Unable to complete friend addition')
