#!/usr/bin/env python3
"""Send keystrokes to the VM's serial console.

Literal text is sent as-is; the braced names below become the control or escape
sequences a terminal would send.

    ./sendkeys.py "{ENTER}"
    ./sendkeys.py "pfctl -t sshguard -T flush{ENTER}"

Note that arrow keys are unreliable in the installer's dialogs: over this serial
console dialog(1) reads the leading ESC of "ESC [ B" as a bare escape and treats
it as cancel. Use {TAB} to move between buttons.
"""
import re
import sys

import lab

KEYS = {
    'ENTER': '\r',
    'TAB': '\t',
    'SPACE': ' ',
    'ESC': '\x1b',
    'BS': '\x7f',
    'UP': '\x1b[A',
    'DOWN': '\x1b[B',
    'RIGHT': '\x1b[C',
    'LEFT': '\x1b[D',
    'CTRL-C': '\x03',
}

out = []
for part in re.split(r'(\{[A-Z-]+\})', ' '.join(sys.argv[1:])):
    name = part[1:-1] if part.startswith('{') and part.endswith('}') else None
    out.append(KEYS[name] if name in KEYS else part)

lab.send(''.join(out))
