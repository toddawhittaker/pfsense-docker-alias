#!/usr/bin/env python3
"""Drive a line-oriented console prompt sequence.

pfSense's console menu asks a series of plain text questions rather than
drawing dialogs, so this waits for each prompt to appear in the console log and
then sends the answer. Matching is against text that has arrived since the
previous step, so a phrase appearing in two prompts cannot make a later step
fire early.

    ./expect.py "Enter an option:=2" "interface you wish=2" ...

Each argument is `substring=response`. The response is sent followed by a
carriage return; an empty response sends a bare carriage return. Exits non-zero
on the first prompt that does not arrive, printing what the console showed
instead.

Prefixing a step with `?` makes it optional: it waits briefly, answers if the
prompt shows up, and otherwise moves on without consuming any output. That is
for questions pfSense asks only sometimes, such as the VLAN prompt on a first
boot where it could not assign the interfaces on its own.
"""
import sys
import time

import lab

TIMEOUT = 120
OPTIONAL_TIMEOUT = 25

# Start a little way back from the end of the log rather than exactly at it:
# the first prompt of a sequence has usually already been printed by the time
# this runs, and seeking to the end would wait forever for output that has
# already arrived.
LOOKBACK = 2000


def read_from(offset):
    with open(lab.CONSOLE_LOG, 'rb') as log:
        log.seek(offset)
        return log.read().decode('utf-8', 'replace')


with open(lab.CONSOLE_LOG, 'rb') as handle:
    handle.seek(0, 2)
    offset = max(0, handle.tell() - LOOKBACK)

for arg in sys.argv[1:]:
    optional = arg.startswith('?')
    marker, _, response = arg.lstrip('?').partition('=')
    deadline = time.time() + (OPTIONAL_TIMEOUT if optional else TIMEOUT)
    matched = True
    while marker not in (fresh := read_from(offset)):
        if time.time() > deadline:
            if optional:
                matched = False
                break
            print(f'TIMEOUT waiting for {marker!r}. Console showed:\n{fresh[-800:]}')
            sys.exit(1)
        time.sleep(1)

    if not matched:
        print(f'  {marker!r} did not appear; skipping (optional)', flush=True)
        continue

    # Consume up to and including the matched prompt so the next step only
    # matches on genuinely new output. An optional step that never matched
    # leaves the offset alone, so a later step can still see this window.
    consumed = fresh[:fresh.index(marker) + len(marker)]
    offset += len(consumed.encode('utf-8', 'replace'))

    print(f'  {marker!r} -> {response!r}', flush=True)
    time.sleep(1)
    lab.send(response + '\r')
