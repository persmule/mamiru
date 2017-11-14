import math
import hashlib
import base64
import json
import pgpdump
import io

def round_offset(offset):
    '''swallow the first two bytes of the body into the header, then round to multiple of 3 to make base64 more efficient'''
    return ceil(((offset + 2) / 3) * 3)

def hashdata(algname, *data):
    md = hashlib.new(algname)
    for b in data:
        md.update(b)
    return md.hexdigest()

def hashverify(algname, hexdigest, *data):
    return bool(hexdigest == hashdata(algname, *data))

def ispgpheader(data):
    if not data:
        raise PgpdumpException("no data to parse")
    if len(data) <= 1:
        raise PgpdumpException("data too short")
    return bool(header[0] & pgpdump.BinaryData.binary_tag_flag)
    
class json_encoder(object):
    def __init__(self, header):
        if not ispgpheader(header):
            raise PgpdumpException("incorrect header")
        
        self.j = dict()
        self.j['header'] = base64.b64encode(header)

    def add_orig_hash(self, algname, hexdigest):
        self.j['origin-hash'] = (algname, hexdigest)

    def add_body_hash(self, algname, hexdigest):
        self.j['body-hash'] = (algname, hexdigest)

    def add_body_url(self, url):
        self.j['body-url'] = url

    def encode(self):
        return json.dumps(self.j)

class json_decoder(object):
    def __init__(self, data):
        if ispgpheader(data):
            self.header = data
            self.ohash = None
            self.bhash = None
        else:
            '''assuming data contains json'''
            j = json.loads(data.decode())
            self.header = base64.b64decode(j['header'])
            try:
                self.ohash = j['origin-hash']
            except KeyError:
                self.ohash = None
            try:
                self.bhash = j['body-hash']
            except KeyError:
                self.bhash = None

    def verify_body(self, body):
        if not self.bhash:
            return None

        return hashverify(self.bhash[0], self.bhash[1], body)

    def verify(self, body):
        if not self.bhash:
            return None

        return hashverify(self.bhash[0], self.bhash[1], self.header, body)

def split(data, offset, bfile):
    header = data[:offset]
    bfile.write(data[offset:])
    return header

def concat(header, body, ofile):
    written = ofile.write(header)
    return written + ofile.write(body)
