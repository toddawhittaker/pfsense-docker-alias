#!/usr/bin/env python3
"""Paths shared by the console helpers.

The VM's state lives outside the repository: the disk image is several
gigabytes and lab.env holds an API key. Set PFSENSE_LAB_DIR to move it.
"""
import os

LAB_DIR = os.environ.get('PFSENSE_LAB_DIR') or os.path.join(
    os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share'),
    'pfsense-docker-alias-lab',
)

CONSOLE_LOG = os.path.join(LAB_DIR, 'console.log')
CONSOLE_FIFO = os.path.join(LAB_DIR, 'console.fifo')
CONSOLE_SOCK = os.path.join(LAB_DIR, 'console.sock')


def send(text):
    """Write keystrokes to the console FIFO that conmux.py is reading."""
    with open(CONSOLE_FIFO, 'wb') as fifo:
        fifo.write(text.encode())
