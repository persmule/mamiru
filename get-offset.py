import sys
import pgpdump
import pgpdump.packet
import mmap
import os

class MmapData(pgpdump.BinaryData):
    '''A wrapper class that does not copy data, designed to operate on mmap of large binary openpgp files'''
    
    def __init__(self, infile):
        data = mmap.mmap(infile.fileno(), 0, prot = mmap.PROT_READ)
        if not data:
            raise PgpdumpException("no data to parse")
        if len(data) <= 1:
            raise PgpdumpException("data too short")

        # 7th bit of the first byte must be a 1
        if not bool(data[0] & self.binary_tag_flag):
            raise PgpdumpException("incorrect binary data")
        self.data = data
        self.length = len(data)

def preread_tag(data, offset):
    tag = data[offset] & 0x3f
    new = bool(data[offset] & 0x40)
    if new:
        return tag
    else:
        return tag >> 2

def packets_at(data):
    '''A generator function returning PGP data packets with its offset.'''
    next_start = 0
    while next_start < data.length:
        total_length, packet = pgpdump.packet.construct_packet(data.data, next_start)
        start = next_start
        next_start += total_length
        yield (packet, start, next_start)


def mapfile(name):
    with open(name, 'rb') as infile:
        data = MmapData(infile)
    return data

def get_sym_start(data):
    '''Get the start offset of Symmetrically Encrypted Data.'''
    start = next_start = 0
    for (packet, start, next_start) in packets_at(data):
        #tag = preread_tag(data.data, start)
        next_tag = preread_tag(data.data, next_start)
        #print((start, packet.length, tag, next_tag))
        if next_tag == 9 or next_tag == 18:
            break

    return next_start


if __name__ == '__main__':
    #import cProfile
    #cProfile.run('main()', 'pgpdump.profile')
    for filename in sys.argv[1:]:
        print('The offset of body of file %s is %u' % (filename, get_sym_start(mapfile(filename))))
