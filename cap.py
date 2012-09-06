"""
CAP parser
"""

import struct
from uuid import UUID

from fd import FD
import guids as g


_SIG_OFFSET = 0
_SIG_SIZE = 0x10

_S_HEADER = struct.Struct('< 16s I I I')
_S_SIGNED_HEADER = struct.Struct('< H H')
_S_FULL_HEADER = struct.Struct('< I 16s I I I I I I I I')


class CAP(object):
    def __init__(self, data, start, prefix=''):
        self.start = start
        self.prefix = prefix
        offset = 0
        (guid_bytes, self.hdrlen, self.flags, self.size) = _S_HEADER.unpack_from(data, offset)
        offset += _S_HEADER.size
        if self.size > len(data):
            raise ValueError('bad size: 0x%x > 0x%x' % (self.size, len(data)))
        self.guid = UUID(bytes_le=guid_bytes)
        self.full_header = False
        self.signed_header = False
        if self.guid == g.EFI_SIGNED_CAPSULE_GUID:
            if self.hdrlen != 0x1C:
                raise ValueError('bad signed header size: 0x%x' % self.hdrlen)
            self.signed_header = True
            (self.body_offset, self.oem_offset) = _S_SIGNED_HEADER.unpack_from(data, offset)
            offset += _S_SIGNED_HEADER.size
        else:
            if self.hdrlen == 0x50:
                self.full_header = True
                (self.sequence_number, self.instance_id, self.split_offset, self.body_offset, self.oem_offset,
                 self.author_string, self.revision_string, self.short_string, self.long_string,
                 self.devices_offset) = _S_FULL_HEADER.unpack_from(data, offset)
                offset += _S_FULL_HEADER.size
            elif self.hdrlen == 0x1C:
                self.body_offset = offset
                self.oem_offset = None
            else:
                raise ValueError('bad header size: 0x%x' % self.hdrlen)
        self.hdr = data[:self.hdrlen]
        self.hdr_ext = data[self.hdrlen:self.body_offset]
        self.data = data[self.body_offset:self.size]
        self.contents = FD(self.data, start + self.body_offset, prefix)

    def __str__(self):
        return '0x%08x+0x%08x: CAP' % (self.start, self.size)

    def showinfo(self, ts='  '):
        print ts + 'Size: 0x%x (header 0x%x) (ext 0x%x) (data 0x%x)' % (self.size, len(self.hdr), len(self.hdr_ext),
                                                                        len(self.data))
        print ts + str(self.contents)
        self.contents.showinfo(ts + '  ')

    def dump(self):
        fnprefix = '%s%08x' % (self.prefix, self.start)
        fn = '%s_cap.bin' % fnprefix
        print 'Dumping CAP header to %s' % fn
        with open(fn, 'wb') as fout:
            fout.write(self.hdr)
            fout.write(self.hdr_ext)

        self.contents.dump()

    @staticmethod
    def check_sig(data, offset=0):
        offset += _SIG_OFFSET
        return data[offset:offset + _SIG_SIZE] in g.CAPSULE_GUIDS
