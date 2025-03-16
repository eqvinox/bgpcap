# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import functools
import socket
import time

import scapy
import scapy.utils

@functools.total_ordering
class Reader:
    def __init__(self, filename, connaddr):
        self.filename = filename
        self.reader = scapy.utils.PcapNgReader(filename)
        _, addr, _ = filename.split("/")
        self.addr = addr.removeprefix("r")
        self.connaddr = connaddr
        self.sock = None
        self.broken = False
        self.pktidx = 0

        self.grab_pkt()

    def grab_pkt(self):
        try:
            self.pkt = self.reader.read_packet()
            self.pktidx += 1
        except EOFError:
            self.pkt = None

    def next_ts(self):
        if self.pkt is None:
            return float("+inf")
        return float(self.pkt.time)

    def __eq__(self, other):
        return self.next_ts() == other.next_ts()
    def __lt__(self, other):
        return self.next_ts() < other.next_ts()

    def do_replay(self, i):
        ts_limit = self.next_ts() + 0.001
        to_send = bytearray()
        while self.next_ts() < ts_limit and len(to_send) < 16384:
            pktb = bytearray(bytes(self.pkt))
            if pktb[18] == 0x01:
                pktb[22] = 0xff
                pktb[23] = 0xff

            to_send += pktb
            self.grab_pkt()

        if self.sock is None:
            af = socket.AF_INET6 if ":" in self.addr else socket.AF_INET
            self.sock = socket.socket(af, socket.SOCK_STREAM, 0)
            self.sock.bind((self.addr, 0))
            self.sock.connect((self.connaddr, 179))

        d = time.time() - t1
        print(f"{d:11.6f} {i:8} {ts_limit:18.6f} {self.pktidx:6} {self.addr} -> {self.connaddr}: {len(to_send)}")
        try:
            self.sock.sendall(to_send, 0)
        except BrokenPipeError:
            sys.stderr.write("\033[91;1mbroken pipe\033[m")
            self.broken = True

    def rx_drop(self):
        if self.broken or self.sock is None:
            return
        self.sock.setblocking(False)
        try:
            d = self.sock.recv(262144, 0)
        except BlockingIOError:
            pass
        self.sock.setblocking(True)


readers = []

with open("replay_list", "r") as fd:
    for line in fd.readlines():
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        if "\t" not in line:
            continue
        filename, connaddr = line.split("\t")
        readers.append(Reader(filename, connaddr))

all_readers = readers[:]

i = 0

t1 = time.time()

def drop():
    for r in all_readers:
        r.rx_drop()

while readers:
    readers.sort()
    reader = readers[0]
    reader.do_replay(i)
    i += 1
    if reader.pkt is None or reader.broken:
        readers.remove(reader)

    drop()

t2 = time.time()

print(f"time taken: {t2-t1}")
import code; code.interact(local={}|globals()|locals())
