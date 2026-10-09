"""selftest.py — run your switch locally and watch port security.

    python selftest.py          # run the example scenarios below
    VS Code: open this file, press F5 (Run and Debug), set breakpoints in switch.py.

No real network is needed: this fakes the raw sockets so your Switch constructs anywhere.
It builds Ethernet frames, sends them into your switch with send(), and prints what your
code printed and which ports it forwarded to. Edit the scenarios at the bottom, or call
send() with your own frames.
"""
import socket
import struct

from switch import Switch   # your solution (bring switch.py + ethernet.py from unit 4)

PORTS = ["p0", "p1", "p2"]   # ports are referenced by index (0,1,2), matching this order

HOST_A = "02:00:00:00:00:0a"
HOST_B = "02:00:00:00:00:0b"
HOST_C = "02:00:00:00:00:0c"
BROADCAST = "ff:ff:ff:ff:ff:ff"


def _mac(m):
    return bytes.fromhex(m.replace(":", ""))


def eth_frame(src_mac, dst_mac=BROADCAST, ethertype=0x0800, payload=b"hello"):
    """Build an Ethernet frame. Port security only looks at the source MAC."""
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype) + payload


class _FakeSock:
    def __init__(self, *a, **k):
        self.sent = []

    def bind(self, *a, **k):
        pass

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def setsockopt(self, *a, **k):
        pass

    def close(self):
        pass


def new_switch():
    """A Switch whose ports use fake sockets, so it runs with no real interfaces."""
    for name, val in (("AF_PACKET", 17), ("SOCK_RAW", 3)):
        if not hasattr(socket, name):
            setattr(socket, name, val)
    if not hasattr(socket, "htons"):
        socket.htons = lambda x: x
    socket.socket = lambda *a, **k: _FakeSock()
    return Switch(PORTS)


def send(sw, frame, port_index, label=""):
    """Send one frame into the switch on a port (by index), and show what happened."""
    before = [len(p.sock.sent) for p in sw.ports]
    print(f"\n>>> {label or 'send'}  (in on port {port_index} = {PORTS[port_index]})")
    sw._process_frame(frame, sw.ports[port_index])     # <-- your code runs here; breakpoint it
    forwarded = [PORTS[i] for i, p in enumerate(sw.ports) if len(p.sock.sent) > before[i]]
    print(f"    forwarded to: {forwarded or 'nobody (dropped)'}")


if __name__ == "__main__":
    sw = new_switch()

    send(sw, eth_frame(HOST_A), 0, "host A on p0 (first MAC the port sees)")
    send(sw, eth_frame(HOST_A), 0, "host A again on p0 (same MAC)")
    send(sw, eth_frame(HOST_B), 0, "host B on p0 (a DIFFERENT MAC on a locked port!)")
    send(sw, eth_frame(HOST_B), 1, "host B on p1 (its own port — fine)")

    print("\nExpected: the first two forward with no alert; host B on p0 prints PORT-SECURITY")
    print("and is dropped; host B on p1 forwards fine. Edit the scenarios or call send() yourself.")
