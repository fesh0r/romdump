#!/usr/bin/env python
"""
Dump EFI fd/rom file
"""

import sys

from rom import ROM


def parse_diskfile(filename):
    print 'Reading %s' % filename
    with open(filename, 'rb') as f:
        d = f.read()

    print 'Parsing %s' % filename
    r = ROM(d)
    print r
    r.showinfo()

    print 'Dumping %s' % filename
    r.dump()


def main():
    if len(sys.argv) > 1:
        for filename in sys.argv[1:]:
            parse_diskfile(filename)
    else:
        print 'No file specified, giving up'


if __name__ == '__main__':
    main()
