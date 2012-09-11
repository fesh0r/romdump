"""
FV parser
"""

import os
import struct
from uuid import UUID

from ffs import FFS
from util import csum16
import guids as g


_SIG = '_FVH'
_SIG_OFFSET = 0x28
_SIG_SIZE = 0x4

_S_HEADER = struct.Struct('< 16s 16s Q 4s I H H H B B')
_S_BLOCK = struct.Struct('< I I')


class FV(object):
    def __init__(self, data, start, prefix=''):
        self.start = start
        self.prefix = prefix
        offset = 0
        (self.boot, guid_bytes, self.size, self.magic, self.attributes, self.hdrlen, self.checksum, self.exthdr,
         self.rsvd, self.revision) = _S_HEADER.unpack_from(data, offset)
        offset += _S_HEADER.size
        if self.magic != _SIG:
            raise ValueError('bad magic: %s' % repr(self.magic))
        if self.size > len(data):
            raise ValueError('bad size: 0x%x > 0x%x' % (self.size, len(data)))
        if self.hdrlen > self.size:
            raise ValueError('bad hdrlen: 0x%x > 0x%x' % (self.hdrlen, self.size))
        self.guid = UUID(bytes_le=guid_bytes)
        if guid_bytes not in g.FFS_GUIDS:
            raise ValueError('unknown guid: %s' % g.name(self.guid))
        self.hdr = data[:self.hdrlen]
        self.checksum_valid = (csum16(self.hdr) == 0)
        self.data = data[self.hdrlen:self.size]
        self.blocks = []
        block_size = 0
        while offset < self.hdrlen:
            (numb, blen) = _S_BLOCK.unpack_from(data, offset)
            offset += _S_BLOCK.size
            if (numb, blen) == (0, 0):
                break
            block_size += numb * blen
            self.blocks.append((numb, blen))
        self.block_size = block_size
        offset = self.hdrlen
        self.files = []
        index = 0
        while offset < self.size:
            padding = data[offset:offset + 8]
            if padding == chr(0xff) * 8:
                offset += 8
                continue
            cur_prefix = '%sffs/%03d_' % (prefix, index)
            cur_file = FFS.new(self.guid, data[offset:], start + offset, cur_prefix)
            offset += cur_file.size
            self.files.append(cur_file)
            index += 1
            padding_size = (8 - (offset & 7)) & 7
            offset += padding_size

    def __str__(self):
        return '0x%08x+0x%08x: FV' % (self.start, self.size)

    def showinfo(self, ts='  '):
        print ts + 'Reserved boot zone: %s' % (' '.join('%02x' % ord(c) for c in self.boot))
        print ts + 'GUID: %s' % g.name(self.guid)
        print ts + 'Size: 0x%x (data 0x%x) (blocks 0x%x)' % (self.size, len(self.data), self.block_size)
        print ts + 'Attributes: 0x%08x' % self.attributes
        print ts + 'Checksum valid: %s' % self.checksum_valid
        print ts + 'Ext header: 0x%04x' % self.exthdr
        print ts + 'Revision: %d' % self.revision
        print ts + 'Blocks:'
        for numb, blen in self.blocks:
            print ts + '  ' + '%d: len 0x%x' % (numb, blen)
        for f in self.files:
            print ts + str(f)
            f.showinfo(ts + '  ')

    def dump(self):
        fnprefix = '%s%08x' % (self.prefix, self.start)
        fn = '%s.fv' % fnprefix
        fn = os.path.normpath(fn)
        print 'Dumping FV  to %s' % fn
        dn = os.path.dirname(fn)
        if dn and not os.path.isdir(dn):
            os.makedirs(dn)
        with open(fn, 'wb') as fout:
            fout.write(self.hdr)
            fout.write(self.data)
        for f in self.files:
            f.dump()

    @staticmethod
    def check_sig(data, offset=0):
        offset += _SIG_OFFSET
        return data[offset:offset + _SIG_SIZE] == _SIG
