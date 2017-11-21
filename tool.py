#!/usr/bin/env python
# -*- coding: utf-8 -*-

# MDict *.mdd and *.mdx data extractor
#
# This program is a free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# You can get a copy of GNU General Public License along this program
# But you can always get it from http://www.gnu.org/licenses/gpl.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

from __future__ import print_function

import os
import sys
import contextlib
import argparse

#from readmdict import MDD, MDX
from mdict import MDD, MDX

def csvquote(s):
    'Quote a CSV field, as in RFC4180'
    if not any(c in s for c in '\n",'):
        return s
    elif '"' in s:
        return '"' + s.replace('"','""') + '"'
    else:
        return '"' + s + '"'

@contextlib.contextmanager
def csvopen(filename=None):
    'Combined interface for file and stdout'
    if filename and filename != '-':
        fh = open(filename, 'wb')
    else:
        fh = sys.stdout
    try:
        yield fh
    finally:
        if fh is not sys.stdout:
            fh.close()

def main():
    # command line argument
    parser = argparse.ArgumentParser(description="mdict tool")
    parser.add_argument('mdict_file',
                        help="Input *.mdx or *.mdd file")
    parser.add_argument('-l', '--list', default=False, action='store_true',
                        help='List entry names in MDX or file names in MDD')
    parser.add_argument('-a', '--dump', default=False, action='store_true',
                        help='Dump all files in *.mdd into files in output dir or ' \
                             'all entries in *.mdx into a CSV')
    parser.add_argument('-x', '--extract',
                        help='Extract one file or entry content, print to stdout if -o not specified. ' \
                             'Argument should be specified in UTF-8')
    parser.add_argument('-d', '--dir',
                        help='Output directory for -a or -o')
    parser.add_argument('-o', '--output',
                        help='Output filename for -x')
    parser.add_argument('-e', '--transcode',
                        help='Transcode data, specified in format of INPUT_ENC:OUTPUT_ENC')
    args = parser.parse_args()

    # open file
    is_mdd = args.mdict_file.lower().endswith('.mdd')
    obj = MDD(args.mdict_file) if is_mdd else MDX(args.mdict_file)
    if args.transcode:
        in_enc, out_enc = args.transcode.split(':')
        assert((in_enc and out_enc) or (not in_enc and not out_enc))
    else:
        in_enc, out_enc = None, None

    # operation depends on input
    if args.list:
        # print all key (entries or filenames)
        for key, _ in obj.items():
            if in_enc and out_enc:
                print(key.decode(in_enc).encode(out_enc))
            else:
                print(key)
    elif args.dump and is_mdd:
        # dump all resources in *.mdd into files
        for filename, blob in obj.items():
            if in_enc:         # transcode filename if needed
                filename = filename.decode(in_enc)
            filename = key     # use entry name as filename
            if args.dir:
                filename = os.path.join(args.dir, filename)
            open(filename, 'wb').write(value)
    elif args.dump and not is_mdd:
        # dump all resources in *.mdx into a CSV file
        newline = '\r\n'
        if args.output:
            filename = args.output
            if args.dir:
                filename = os.path.join(args.dir, filename)
	else:
            filename = '-'
        with csvopen(filename) as fh:
            for key, val in obj.items():
                if in_enc:         # transcode key & val if needed
                    key = key.decode(in_enc)
                    val = val.decode(in_enc).encode(out_enc)
                fh.write(csvquote(key))
                fh.write(',')
                fh.write(csvquote(val))
                fh.write(newline)
    elif args.extract:
        # find entry/filename, write definition/blob
        target = args.extract.decode('utf-8')
        for key, value in obj.items():
            if in_enc:             # transcode key if needed
                key = key.decode(in_enc)
            if key != target:      # seek until we find the target
                continue
            if in_enc and out_enc: # transcode value if needed
                value = value.decode(in_enc).encode(out_enc)
            filename = args.output
            if args.dir and is_mdd:# data from *.mdd has its default filename
                filename = key
            if not filename:       # print to console or save to file
                print(value)
            else:
                filename = args.output
                if args.dir:
                    filename = os.path.join(args.dir, filename)
                open(filename, 'wb').write(value)

if __name__ == '__main__':
    main()
