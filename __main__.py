#!/usr/bin/env python

import sys
import argparse
import get_offset
import tool

def split(args):
    d = get_offset.RawData(get_offset.mapfile(args.ifile))
    off = get_offset.get_sym_start(d)
    new_off = tool.round_offset(off)
    print('The offset of %s is %u, rounded to %u' % (args.ifile, off, new_off), file=sys.stderr);
    if args.json:
        with open(args.header, 'w') as h:
            print('Encoding header as json...', file=sys.stderr)
            je = tool.json_encoder(d.data[:new_off])
            
            if args.orighash:
                hsum = tool.hashdata(args.orighash, d.data)
                print('Adding %s hash of original file %s...'
                      % (args.orighash, hsum),
                      file=sys.stderr)
                je.add_orig_hash(args.orighash, hsum)

            if args.bodyhash:
                hsum = tool.hashdata(args.bodyhash, d.data[new_off:])
                je.add_body_hash(args.bodyhash, hsum)
                print('Adding %s hash of the body part %s...'
                      % (args.bodyhash, hsum),
                      file=sys.stderr)
                
            h.write(je.encode())
            h.write('\n')
    else:
        with open(args.header, 'wb') as h:
            h.write(d.data[:new_off])

    with open(args.body, 'wb') as b:
        b.write(d.data[new_off:])

def concat(args):
    jd = tool.json_decoder(get_offset.mapfile(args.header))
    b = get_offset.mapfile(args.body)
    if args.verify:
        if jd.ohash:
            isvalid, hsum = jd.verify(b) 
            print('Integrity of all data provided is %s: %s'
                  % ('valid' if isvalid else 'invalid', hsum),
                  file=sys.stderr)

        if jd.bhash:
            isvalid, hsum = jd.verify_body(b)
            print('Integrity of the body part is %s: %s'
                  % ('valid' if isvalid else 'invalid', hsum),
                  file=sys.stderr)

    ofile = open(args.output, 'wb') if args.output else sys.stdout
    tool.concat(jd.header, b, ofile)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='OpenPGP Binary Encrypted File Splitter.')
    s = p.add_subparsers(help='sub-command help', dest='subparser_name')
    s_split = s.add_parser('split', aliases='s', help='split an OpenPGP Binary file')
    s_split.add_argument('--ifile', '-i', help='path to input file', required=True)
    s_split.add_argument('--header', '-m', help='path to output header file', required=True)
    s_split.add_argument('--body', '-b', help='path to output body file', required=True)
    s_split.add_argument('--json', '-j', help='encode header file as json', action='store_true')
    s_split.add_argument('--bodyhash', '-B', help='insert a hash for body into the json-formatted header', action='store_const', const='sha256')
    s_split.add_argument('--orighash', '-O', help='insert a hash for input file into the json-formatted header', action='store_const', const='sha256')
    s_split.set_defaults(func=split)
    s_cat = s.add_parser('concat', aliases='c', help='concatenate a header and a body into an intact OpenPGP file')
    s_cat.add_argument('--header', '-m', help='path to header file', required=True)
    s_cat.add_argument('--body', '-b', help='path to body file', required=True)
    s_cat.add_argument('--output', '-o', help='path to output, default to stdout')
    s_cat.add_argument('--verify', '-c', help='perform verification if any hashe is present in the json-encoded header', action='store_true')
    s_cat.set_defaults(func=concat)

    args = p.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        p.print_usage()
