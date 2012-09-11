"""
FFS parser
"""

import struct
from uuid import UUID

from raw import RAW
import guids as g


_S_HEADER = struct.Struct('< 16s BB B B BBB B')
_S_EXT_SIZE = struct.Struct('< L')


class FFS(object):
    def __init__(self, revision, data, start, prefix=''):
        self.start = start
        self.prefix = prefix
        self.revision = revision

        offset = 0
        (guid, self.header_csum, self.file_csum, self.file_type, self.attributes, size_lo, size_mid, size_hi,
         self.state) = _S_HEADER.unpack_from(data, offset)
        offset += _S_HEADER.size
        self.guid = UUID(bytes_le=guid)
        self.int_check = self.header_csum | (self.file_csum << 8)
        self.size = size_lo | (size_mid << 8) | (size_hi << 16)
        self.has_tail = False
        if self.revision == 1 and (self.attributes & 1):
            self.has_tail = True
        self.large_file = False
        if self.revision == 3 and (self.attributes & 1):
            self.large_file = True
            extended_size, = _S_EXT_SIZE.unpack_from(data, offset)
            offset += _S_EXT_SIZE.size
            self.size = extended_size
        self.data = data[offset:self.size]
        self.contents = RAW(self.data, None, prefix + 'f')

    def __str__(self):
        return '0x%08x+0x%08x: FFS' % (self.start, self.size)

    def showinfo(self, ts='  '):
        print ts + 'Size: 0x%x (data 0x%x)' % (self.size, len(self.data))
        print ts + 'Name: %s' % g.name(self.guid)
        print ts + 'Type: 0x%02x' % self.file_type
        print ts + 'Check: 0x%04x' % self.int_check
        print ts + 'Attributes: 0x%02x' % self.attributes
        print ts + 'State: 0x%02x' % self.state
        print ts + 'Has tail: %s' % self.has_tail
        print ts + 'Large file: %s' % self.large_file
        print ts + str(self.contents)
        self.contents.showinfo(ts + '  ')

    def dump(self):
        self.contents.dump()

    @staticmethod
    def new(ffs_guid, data, start, prefix=''):
        if ffs_guid == g.EFI_FIRMWARE_FILE_SYSTEM_GUID:
            return FFS(1, data, start, prefix)
        elif ffs_guid == g.EFI_FIRMWARE_FILE_SYSTEM2_GUID:
            return FFS(2, data, start, prefix)
        elif ffs_guid == g.EFI_FIRMWARE_FILE_SYSTEM3_GUID:
            return FFS(3, data, start, prefix)
        else:
            raise ValueError('Unknown FFS guid: %s' % g.name(ffs_guid))
