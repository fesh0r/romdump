#!/usr/bin/env python
"""
Dump EFI FIRMWARE FILE SYSTEM
"""

import sys
import struct
from uuid import UUID

import guids as g


class FFSSection(object):
    def __init__(self, data):
        hdr = data[:0x4]
        (self.size, self.type) = struct.unpack('<3sB', hdr)
        self.size = struct.unpack('<I', self.size + "\x00")[0]
        data = data[0x4:self.size]
        self.data = data
        self.subsections = None
        self.name = None
        if self.type == 0x02:
            dguid = UUID(bytes_le=self.data[:16])
            if dguid == g.EFI_SECTION_CRC32_GUID:
                self.subsections = []
                data = data[0x18:]
                while len(data):
                    s = FFSSection(data)
                    self.subsections.append(s)
                    data = data[(s.size + 3) & (~3):]
        elif self.type == 0x15:
            self.name = self.data.decode('utf-16le').split("\0")[0]

    def showinfo(self, ts=''):
        if self.type == 0x01:
            print ts + 'Compression section'
        elif self.type == 0x02:
            print ts + 'GUID-defined section'
            if self.subsections is not None:
                print ts + ' CRC32 subsection container:'
                for i, s in enumerate(self.subsections):
                    print ts + '  Subsection %d: type 0x%02x, size 0x%x' % (i, s.type, s.size)
                    s.showinfo(ts + '   ')
        elif self.type == 0x03:
            print ts + 'Disposable section'
        elif self.type == 0x10:
            print ts + 'PE Image'
        elif self.type == 0x11:
            print ts + 'PE PIC Image'
        elif self.type == 0x12:
            print ts + 'TE Image'
        elif self.type == 0x13:
            print ts + 'DXE Dependency Expression'
        elif self.type == 0x14:
            print ts + 'Version'
        elif self.type == 0x15:
            print ts + 'User Interface name:', self.name
        elif self.type == 0x16:
            print ts + 'Compatibility16'
        elif self.type == 0x17:
            print ts + 'Firmware Volume Image'
        elif self.type == 0x18:
            print ts + 'Freeform Subtype GUID'
        elif self.type == 0x19:
            print ts + 'RAW'
        elif self.type == 0x1b:
            print ts + 'PEI Dependency Expression'
        elif self.type == 0x1c:
            print ts + 'SMM Dependency Expression'
        else:
            print ts + 'Unknown section type'

    def dump(self, base):
        if self.subsections is not None:
            for i, s in enumerate(self.subsections):
                s.dump('%s.sub%d' % (base, i))
            return

        ext = {
            0x01: 'compression',
            0x02: 'guiddef',
            0x03: 'disp',
            0x10: 'pe',
            0x11: 'pic.pe',
            0x12: 'te',
            0x13: 'dxe.depex',
            0x14: 'ver',
            0x15: 'name',
            0x16: '16bit',
            0x17: 'fvi',
            0x18: 'guid',
            0x19: 'raw',
            0x1b: 'pei.depex',
            0x1c: 'smm.depex'
        }.get(self.type, 'unknown.bin')

        name = '%s.%s' % (base, ext)
        fd = open(name, 'wb')
        fd.write(self.data)
        fd.close()
        print name


class FFSFile(object):
    def __init__(self, data):
        hdr = data[:0x18]
        (guid, self.checksum, self.type, self.attributes, self.size, self.state) = struct.unpack('<16sHBB3sB', hdr)
        self.guid = UUID(bytes_le=guid)
        self.size = struct.unpack('<I', self.size + chr(0))[0]
        data = data[0x18:self.size]
        self.data = data
        if self.type == 0xf0:
            self.sections = None
        else:
            self.sections = []
            while len(data):
                s = FFSSection(data)
                self.sections.append(s)
                data = data[(s.size + 3) & (~3):]

    def showinfo(self, ts=''):
        print ts + 'GUID:', self.guid
        print ts + 'Size: 0x%x (data 0x%x)' % (self.size, len(self.data))
        print ts + 'Type: 0x%02x' % self.type
        print ts + 'Attributes: 0x%02x' % self.attributes
        print ts + 'State: 0x%02x' % (self.state ^ 0xFF)
        if self.sections is not None:
            for i, s in enumerate(self.sections):
                print ts + ' Section %d: type 0x%02x, size 0x%x' % (i, s.type, s.size)
                s.showinfo(ts + '  ')
        else:
            print ts + 'This is a padding file'

    def dump(self):
        if self.sections is not None:
            appn = ''
            for s in self.sections:
                if s.name is not None:
                    appn = '-' + s.name
                elif s.subsections is not None:
                    for s in s.subsections:
                        if s.name is not None:
                            appn = '-' + s.name
            for i, s in enumerate(self.sections):
                s.dump('%s%s.sec%d' % (self.guid, appn, i))


class FS(object):
    def __init__(self, data):
        self.files = []
        while len(data) and data[:16] != (chr(0xFF) * 16):
            f = FFSFile(data)
            self.files.append(f)
            data = data[(f.size + 7) & (~7):]

    def showinfo(self, ts=''):
        for i, f in enumerate(self.files):
            print ts + 'File %d:' % i
            f.showinfo(ts + ' ')

    def dump(self):
        for f in self.files:
            f.dump()


def main():
    with open(sys.argv[1], 'rb') as f:
        d = f.read()

    fs = FS(d)

    print 'Filesystem:'
    fs.showinfo('  ')
#    print 'Dumping...'
#    fs.dump()


if __name__ == '__main__':
    main()
