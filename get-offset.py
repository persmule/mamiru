import sys
import pgpdump
import mmap
import os

class MmapData(pgpdump.BinaryData):
    '''A wrapper class that does not copy data, designed to operate on mmap of large binary openpgp files'''
    pagesize = 4096
    
    def __init__(self, infile):
        self.pages = 2
        data = mmap.mmap(infile.fileno(), 0, prot = mmap.PROT_READ)
        if not data:
            raise PgpdumpException("no data to parse")
        if len(data) <= 1:
            raise PgpdumpException("data too short")

        # 7th bit of the first byte must be a 1
        if not bool(data[0] & self.binary_tag_flag):
            raise PgpdumpException("incorrect binary data")
        self.data = data
        self.infile = infile
        self.length = os.stat(infile.fileno()).st_size

    def getdata(self):
        return self.data

def mapfile(name):
    with open(name, 'rb') as infile:
        data = MmapData(infile)
    return data

def parsedata(data):
    for packet in data.packets():
        yield packet

def get_offset(data):
    counter = offset = 0
    for packet in parsedata(data):
        if packet.raw == 9 or packet.raw == 18:
            break
        counter += 1
        offset += packet.length

    return offset


if __name__ == '__main__':
    #import cProfile
    #cProfile.run('main()', 'pgpdump.profile')
    for filename in sys.argv[1:]:
        print('The offset of body of file %s is %u' % (filename, get_offset(mapfile(filename))))
