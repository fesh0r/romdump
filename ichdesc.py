"""
ICH flash descriptor
"""

import struct

from raw import RAW
from fd import FD


_SIG = '5AA5F00F'.decode('hex')
_SIG_OFFSET = 0x10
_SIG_SIZE = 0x4

_S_HEADER = struct.Struct('< 16s 4s BBBB BBBB BBBB')
_S_REGION = struct.Struct('< H H')

_REGIONS = [('ich', RAW), ('bios', FD), ('me', RAW), ('gbe', RAW), ('plat', RAW)]


class ICHDesc(object):
    def __init__(self, data, start, prefix=''):
        self.start = start
        self.prefix = prefix
        offset = 0
        (self.rsvd, self.flvalsig, fcba, nc, frba, nr, fmba, nm, fpsba, isl,
         fmsba, psl, _, _) = _S_HEADER.unpack_from(data, offset)
        offset += _S_HEADER.size
        if self.flvalsig != _SIG:
            raise ValueError('bad magic %s' % repr(self.flvalsig))

        self.fcba = fcba << 4
        self.nc = nc + 1
        self.frba = frba << 4
        self.nr = nr + 1
        self.fmba = fmba << 4
        self.nm = nm + 1
        self.fpsba = fpsba << 4
        self.isl = isl
        self.fmsba = fmsba << 4
        self.psl = psl

        self.blocks = []
        self.regions = []
        offset = self.frba
        region_size = 0
        for name, class_ in _REGIONS:
            (base, limit) = _S_REGION.unpack_from(data, offset)
            offset += _S_REGION.size
            if limit >= base:
                base = base << 12
                limit = (limit << 12) | 0xfff
                region_size += limit - base + 1
                cur_prefix = '%s%s_' % (prefix, name)
                self.blocks.append(class_(data[base:limit + 1], start + base, cur_prefix))
            else:
                base = None
                limit = None
                self.blocks.append(None)
            self.regions.append((base, limit))
        self.size = region_size

    def __str__(self):
        return '0x%08x+0x%08x: ICH' % (self.start, self.size)

    def showinfo(self, ts='  '):
        print ts + 'Size: 0x%x' % self.size
        print ts + 'Reserved: %s' % (' '.join('%02x' % ord(c) for c in self.rsvd))
        print ts + 'FR:  0x%03x %2d' % (self.frba, self.nr)
        print ts + 'FC:  0x%03x %2d' % (self.fcba, self.nc)
        print ts + 'FPS: 0x%03x %2d' % (self.fpsba, self.isl)
        print ts + 'FM:  0x%03x %2d' % (self.fmba, self.nm)
        print ts + 'FMS: 0x%03x %2d' % (self.fmsba, self.psl)
        print ts + 'Regions:'
        for index, (name, _) in enumerate(_REGIONS):
            (base, limit) = self.regions[index]
            if base is None:
                print ts + '  ' + '%4s:-' % name
            else:
                print ts + '  ' + '%4s:0x%06x:0x%06x' % (name, base, limit)

        for block in self.blocks:
            if block:
                print ts + str(block)
                block.showinfo(ts + '  ')

    def dump(self):
        for block in self.blocks:
            if block:
                block.dump()

    @staticmethod
    def check_sig(data, offset=0):
        offset += _SIG_OFFSET
        return data[offset:offset + _SIG_SIZE] == _SIG
