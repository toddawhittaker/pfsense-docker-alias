#!/usr/bin/env python3
"""Drive the pfSense installer's dialog screens over the serial console.

Sending keystrokes on a timer does not work: a screen that takes longer than
expected swallows the keys meant for the next one. So this waits for the screen
to settle, matches it against the rule table, sends that rule's keys, and waits
for the screen to change before matching again. If nothing matches for long
enough it prints the screen and fails, rather than guessing.

Two details are load-bearing:

* Arrow keys must not be used. Over this serial console dialog(1) reads the
  leading ESC of "ESC [ B" as a bare escape and cancels the dialog, which quits
  the installer to a login prompt. TAB moves between buttons instead.
* The "Last Chance" confirmation defaults to NO, and nothing on a monochrome
  screen distinguishes the focused button except that dialog draws its brackets
  in bold. showcon.py marks bold with single angle quotes, which is what lets
  the rules below tell "focus is on NO, press TAB" from "focus is on YES, press
  ENTER" instead of pressing blind.

Those markers are also why matching happens against the marked screen and a
marker-stripped copy of it together. dialog highlights the hotkey letter inside
a word, so the marked screen renders "vtbd0" as "‹v›tbd0" and a plain substring
search for the device name silently never matches.
"""
import hashlib
import os
import subprocess
import sys
import time

import lab

HERE = os.path.dirname(os.path.abspath(__file__))

ENTER = '\r'
SPACE = ' '
TAB = '\t'

# (description, [every one of these must be on screen], keys, is_last_step)
RULES = [
    ('console type',        ['Console type'],                             ENTER, False),
    ('copyright notice',    ['Copyright', 'Accept'],                      ENTER, False),
    ('welcome menu',        ['Welcome to pfSense!', 'Install pfSense'],   ENTER, False),
    ('partitioning',        ['How would you like to partition'],          ENTER, False),
    ('zfs menu',            ['ZFS Configuration', 'Proceed with'],        ENTER, False),
    ('vdev type',           ['Virtual Device type'],                      ENTER, False),
    ('select the disk',     ['vtbd0', '[ ]'],                             SPACE, False),
    ('confirm the disk',    ['vtbd0', '[*]'],                             ENTER, False),
    ('last chance, on NO',  ['Last Chance', '‹<› NO'],          TAB,   False),
    ('last chance, on YES', ['Last Chance', '‹<› YES'],         ENTER, False),
    ('reboot when done',    ['Installation of pfSense complete'],         ENTER, True),
]

OVERALL_TIMEOUT = 1800
NO_MATCH_TIMEOUT = 600   # the install itself shows a progress screen for a while


MARKERS = str.maketrans('', '', '«»‹›')


def screen():
    """The rendered screen, followed by the same screen without focus markers.

    Rules are matched against the pair, so a rule can ask about focus using the
    markers while a rule about ordinary text is not defeated by a marker landing
    in the middle of a word.
    """
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, 'showcon.py'), lab.CONSOLE_LOG],
        capture_output=True, text=True, check=True,
    )
    marked = out.stdout
    return marked + '\n' + marked.translate(MARKERS)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def settle(quiet=3.0, timeout=300):
    """Wait until the screen stops changing for `quiet` seconds."""
    deadline = time.time() + timeout
    last, last_change = None, time.time()
    while time.time() < deadline:
        current = digest(screen())
        if current != last:
            last, last_change = current, time.time()
        elif time.time() - last_change >= quiet:
            return
        time.sleep(1)


started = time.time()
unmatched_since = None

while True:
    if time.time() - started > OVERALL_TIMEOUT:
        print('installer did not finish within the overall timeout')
        print(screen())
        sys.exit(1)

    settle()
    view = screen()

    for name, markers, keys, is_last in RULES:
        if all(marker in view for marker in markers):
            print(f'  {name}', flush=True)
            unmatched_since = None
            before = digest(view)
            lab.send(keys)
            if is_last:
                print('installer finished', flush=True)
                sys.exit(0)
            for _ in range(120):
                time.sleep(1)
                if digest(screen()) != before:
                    break
            break
    else:
        now = time.time()
        unmatched_since = unmatched_since or now
        if now - unmatched_since > NO_MATCH_TIMEOUT:
            print('no installer screen matched for too long. Console showed:\n')
            print(view)
            sys.exit(1)
        time.sleep(5)
