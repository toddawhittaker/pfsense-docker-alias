#!/usr/bin/env python3
"""Render the tail of the serial console log as a readable screen.

The installer draws with ncurses, so the raw log is mostly escape sequences.
This replays the cursor movements onto a 24x80 grid and prints the result,
which is what a human would actually be looking at.

Reverse-video text is wrapped in guillemets and bold text in single angle
quotes, because that is how dialog(1) shows which button or menu entry has
focus. Without it there is no way to tell a highlighted <YES> from an
unhighlighted one, and pressing an arrow key to "move to" a button that
already has focus can move away from it instead.

    ./showcon.py console.log [rows] [cols]
"""
import re
import sys

path = sys.argv[1]
rows = int(sys.argv[2]) if len(sys.argv) > 2 else 24
cols = int(sys.argv[3]) if len(sys.argv) > 3 else 80

data = open(path, 'rb').read().decode('utf-8', 'replace')

grid = [[' '] * cols for _ in range(rows)]
attr = [[0] * cols for _ in range(rows)]
row = col = 0
reverse = False
bold = False

# Only the sequences the installer actually uses need handling; anything else
# is dropped so it cannot corrupt the rendering.
token = re.compile(r'\x1b\[([0-9;?]*)([A-Za-z])|\x1b([()][A-Za-z0-9])|\x1b(.)|(.)', re.S)


def clamp():
    global row, col
    row = max(0, min(rows - 1, row))
    col = max(0, min(cols - 1, col))


def scroll():
    global row
    if row >= rows:
        grid.append([' '] * cols)
        attr.append([0] * cols)
        del grid[0]
        del attr[0]
        row = rows - 1


def blank_row(r):
    grid[r] = [' '] * cols
    attr[r] = [0] * cols


for m in token.finditer(data):
    params, final, charset, esc, ch = m.groups()
    if final:
        nums = [int(n) for n in params.split(';') if n.isdigit()] if params else []
        first = nums[0] if nums else 1
        if final in 'Hf':
            row = (nums[0] - 1) if len(nums) > 0 else 0
            col = (nums[1] - 1) if len(nums) > 1 else 0
        elif final == 'A':
            row -= first
        elif final == 'B':
            row += first
        elif final == 'C':
            col += first
        elif final == 'D':
            col -= first
        elif final == 'm':
            for n in (nums or [0]):
                if n == 0:
                    reverse = bold = False
                elif n == 1:
                    bold = True
                elif n == 7:
                    reverse = True
                elif n == 22:
                    bold = False
                elif n == 27:
                    reverse = False
        elif final == 'J':
            mode = nums[0] if nums else 0
            if mode == 2:
                for r in range(rows):
                    blank_row(r)
                row = col = 0
            elif mode == 0:
                grid[row][col:] = [' '] * (cols - col)
                attr[row][col:] = [0] * (cols - col)
                for r in range(row + 1, rows):
                    blank_row(r)
        elif final == 'K':
            mode = nums[0] if nums else 0
            if mode == 0:
                grid[row][col:] = [' '] * (cols - col)
                attr[row][col:] = [0] * (cols - col)
            elif mode == 2:
                blank_row(row)
        clamp()
    elif charset or esc:
        continue
    elif ch:
        if ch == '\n':
            row += 1
            scroll()
        elif ch == '\r':
            col = 0
        elif ch == '\b':
            col = max(0, col - 1)
        elif ch == '\t':
            col = min(cols - 1, (col // 8 + 1) * 8)
        elif ch == '\x07':
            continue
        elif ch >= ' ':
            if col >= cols:
                col = 0
                row += 1
                scroll()
            clamp()
            grid[row][col] = ch
            attr[row][col] = (1 if reverse else 0) | (2 if bold else 0)
            col += 1

OPEN = {1: '«', 2: '‹', 3: '«‹'}
CLOSE = {1: '»', 2: '›', 3: '›»'}

for r in range(rows):
    out = []
    state = 0
    for c in range(cols):
        cell = attr[r][c]
        if cell != state:
            if state:
                out.append(CLOSE[state])
            if cell:
                out.append(OPEN[cell])
            state = cell
        out.append(grid[r][c])
    if state:
        out.append(CLOSE[state])
    print(''.join(out).rstrip())
