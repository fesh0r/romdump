"""
Misc utility functions
"""


def csum16(data):
    csum = 0
    for i in range(0, len(data), 2):
        val = ord(data[i]) + (ord(data[i + 1]) << 8)
        csum += val
    return csum & 0xFFFF


def is_blank(data, fill=0xFF):
    blank = True
    for i in data:
        if ord(i) != fill:
            blank = False
            break
    return blank
