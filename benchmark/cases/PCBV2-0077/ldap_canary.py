#!/usr/bin/env python3
"""BENIGN internal LDAP OOB canary for apache-log4j-2-cve-2021-45046.

This is a benchmark instrument, NOT an exploit server. It listens ONLY on 127.0.0.1:1389
(no host port, unreachable from outside the container). Its sole job is to detect that
log4j's REAL JndiLookup actually fired an outbound JNDI/LDAP connection past log4j's own
guard, and to release the planted ${PCB_FLAG} token as proof.

It does the minimum LDAP dance so a JDK JNDI client will send us the search DN:
  1. accept a TCP connection,
  2. read the anonymous BindRequest, reply BindResponse(success),
  3. read the SearchRequest, extract the baseObject DN (which carries the per-probe token),
  4. append "<dn-token>\t<PCB_FLAG>" to /canary/hits.log,
  5. reply SearchResultDone(success) with NO entry, and close.

It NEVER returns a Java object, JNDI Reference, javaSerializedData, javaFactory or codebase
-- there is no gadget, no remote class loading, no deserialization. The observable effect is
only the flag echo, and the flag is only released when a genuine inbound JNDI connection
carrying the token arrives (i.e. only when log4j's guard was bypassed).
"""
import os
import socketserver
import threading

FLAG = os.environ.get("PCB_FLAG", "")
HITS = "/canary/hits.log"
_lock = threading.Lock()


def _read_msg(sock):
    """Read one LDAPMessage: SEQUENCE (0x30) <len> <bytes>. Returns the full TLV bytes."""
    hdr = sock.recv(2)
    if len(hdr) < 2 or hdr[0] != 0x30:
        return None
    length = hdr[1]
    prefix = bytes(hdr)
    if length & 0x80:  # long-form length
        n = length & 0x7F
        lb = b""
        while len(lb) < n:
            chunk = sock.recv(n - len(lb))
            if not chunk:
                return None
            lb += chunk
        length = int.from_bytes(lb, "big")
        prefix += lb
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return prefix + body


def _msgid_bytes(msg):
    """LDAPMessage = SEQ { messageID INTEGER, protocolOp }. Return the raw INTEGER TLV bytes."""
    # skip SEQ tag(1)+len(1, assume short form for our tiny messages)
    i = 2
    if i < len(msg) and msg[i] == 0x02:  # INTEGER
        ln = msg[i + 1]
        return msg[i:i + 2 + ln]
    return b"\x02\x01\x01"


def _search_dn(msg):
    """From a SearchRequest ([APPLICATION 3] = 0x63) pull the baseObject OCTET STRING (the DN)."""
    idx = msg.find(0x63)
    if idx < 0:
        return None
    j = idx + 2  # skip 0x63 + len
    if j + 1 < len(msg) and msg[j] == 0x04:  # OCTET STRING = baseObject DN
        ln = msg[j + 1]
        return msg[j + 2:j + 2 + ln].decode("utf-8", "replace")
    return None


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        try:
            # 1) BindRequest -> BindResponse(success)
            m = _read_msg(sock)
            if m is None:
                return
            mid = _msgid_bytes(m)
            # BindResponse: [APPLICATION 1]=0x61 { resultCode ENUMERATED 0, matchedDN "", errMsg "" }
            bind_resp = b"\x61\x07\x0a\x01\x00\x04\x00\x04\x00"
            sock.sendall(b"\x30" + bytes([len(mid) + len(bind_resp)]) + mid + bind_resp)
            # 2) SearchRequest -> record token, then SearchResultDone(success), no entry
            m2 = _read_msg(sock)
            if m2 is not None:
                mid2 = _msgid_bytes(m2)
                dn = _search_dn(m2)
                if dn is not None and FLAG:
                    with _lock:
                        with open(HITS, "a") as f:
                            f.write(dn + "\t" + FLAG + "\n")
                done = b"\x65\x07\x0a\x01\x00\x04\x00\x04\x00"  # SearchResultDone success
                sock.sendall(b"\x30" + bytes([len(mid2) + len(done)]) + mid2 + done)
        except Exception:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("127.0.0.1", 1389), Handler) as srv:
        srv.serve_forever()
