"""
NCB
"""

from util import is_blank


class RAW(object):
    def __init__(self, data, start, prefix=''):
        self.start = start
        self.prefix = prefix
        self.data = data
        self.size = len(data)
        self.is_blank = is_blank(data)

    def __str__(self):
        return '0x%08x+0x%08x: RAW' % (self.start, self.size)

    def showinfo(self, ts='  '):
        print ts + 'Size: 0x%x' % self.size
        print ts + 'Blank: %s' % self.is_blank

    def dump(self):
        fnprefix = '%s%08x' % (self.prefix, self.start)
        if self.is_blank:
            fn = '%s_empty.bin' % fnprefix
        else:
            fn = '%s.bin' % fnprefix
        print 'Dumping RAW to %s' % fn
        with open(fn, 'wb') as fout:
            fout.write(self.data)
