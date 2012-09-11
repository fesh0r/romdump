"""
NCB
"""

import os

from util import is_blank


class RAW(object):
    def __init__(self, data, start, prefix=''):
        self.start = start
        self.prefix = prefix
        self.data = data
        self.size = len(data)
        self.is_blank = is_blank(data)

    def __str__(self):
        if self.start is None:
            return '??????????+0x%08x: RAW' % self.size
        else:
            return '0x%08x+0x%08x: RAW' % (self.start, self.size)

    def showinfo(self, ts='  '):
        print ts + 'Size: 0x%x' % self.size
        print ts + 'Blank: %s' % self.is_blank

    def dump(self):
        if self.start is None:
            fnprefix = self.prefix
        else:
            fnprefix = '%s%08x' % (self.prefix, self.start)
        fn = '%s.bin' % fnprefix
        fn = os.path.normpath(fn)
        print 'Dumping RAW to %s' % fn
        dn = os.path.dirname(fn)
        if dn and not os.path.isdir(dn):
            os.makedirs(dn)
        with open(fn, 'wb') as fout:
            fout.write(self.data)
