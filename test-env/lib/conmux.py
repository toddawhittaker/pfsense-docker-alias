#!/usr/bin/env python3
"""Multiplex the VM's serial console.

QEMU's chardev socket accepts one client at a time, so a single process owns
it. Everything the console prints is appended to a log file, and anything
written to a FIFO is sent to the console as keystrokes. That lets the other
helpers both watch and drive the console without fighting over the socket.

    ./conmux.py console.sock console.log console.fifo
"""
import os
import selectors
import socket
import sys

sock_path, log_path, fifo_path = sys.argv[1:4]

if not os.path.exists(fifo_path):
    os.mkfifo(fifo_path)

console = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
console.connect(sock_path)
console.setblocking(False)

log = open(log_path, 'ab', buffering=0)

# Opening the FIFO read-write keeps it open across writer disconnects, so the
# selector does not spin on EOF every time a writer finishes.
fifo = os.open(fifo_path, os.O_RDWR | os.O_NONBLOCK)

sel = selectors.DefaultSelector()
sel.register(console, selectors.EVENT_READ, 'console')
sel.register(fifo, selectors.EVENT_READ, 'fifo')

# pfSense runs resizewin from its shell profile, which asks the terminal how
# big it is and blocks until it answers. Nothing here is a real terminal, so
# without these replies every shell prompt stalls and fills the log with
# "resizewin: timeout reading from terminal".
ANSWERS = {
    b'\x1b[6n': b'\x1b[24;80R',      # cursor position report
    b'\x1b[18t': b'\x1b[8;24;80t',   # window size in characters
}

while True:
    for key, _ in sel.select():
        if key.data == 'console':
            data = console.recv(65536)
            if not data:
                sys.exit(0)
            log.write(data)
            for query, answer in ANSWERS.items():
                if query in data:
                    console.sendall(answer)
        else:
            data = os.read(fifo, 65536)
            if data:
                console.sendall(data)
