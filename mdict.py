#!/usr/bin/env python
# -*- coding: utf-8 -*-

# mdict.py
#
# Trimmed-down, refactored version of Octopus MDict Dictionary File (.mdx) and
# Resource File (.mdd) Analyser by Xiaoquing Wang
# <https://bitbucket.org/xwang/mdict-analysis>
#
# This package includes ripemd128 and Salsa20 implementation by
# <https://github.com/zhansliu/writemdict>
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

import json
import math
import re
import sys
import zlib # zlib compression is used for engine version >=2.0

from struct import pack, unpack, Struct
from io import BytesIO

assert(sys.version_info >= (2, 6))
if sys.version_info >= (3,):
    integer_types = (int,)
    unicode = str # 2x3 compatible
    python3 = True
else:
    integer_types = (int, long)
    python3 = False

#########
# For LZO decompression
#
class FlexBuffer():
    def __init__(self):
        self.blockSize = None
        self.c = None
        self.l = None
        self.buf = None
    def require(self, n):
        r = self.c - self.l + n
        if r > 0:
            self.l = self.l + self.blockSize * math.ceil(r / self.blockSize)
            self.buf = self.buf + bytearray(self.l - len(self.buf))
        self.c = self.c + n
        return self.buf
    def alloc(self, initSize, blockSize):
        sz = blockSize or 4096
        self.blockSize = self.roundUp(sz)
        self.c = 0
        self.l = self.roundUp(initSize) | 0
        self.l += self.blockSize - (self.l % self.blockSize)
        self.buf = bytearray(self.l)
        return self.buf
    def roundUp(self, n):
        r = n % 4
        return n if r==0 else (n+4-r)
    def reset(self):
        self.c = 0
        self.l = len(self.buf)
    def pack(self, size):
        return self.buf[0:size]

def _decompress(inBuf, outBuf):
    # state label as constants
    c_top_loop, c_first_literal_run, c_match, c_copy_match, c_match_done, c_match_next = range(6)

    out = outBuf.buf
    op = ip = m_pos = 0
    t = inBuf[ip]
    state = c_top_loop

    def copy(inbuffer, outbuffer, iptr, optr, counter, k):
        for i in range(k):
            outbuffer[optr+i] = inbuffer[iptr+i]
        return iptr+k, optr+k, counter-k

    if t > 17:
        ip = ip + 1
        t = t - 17
        if t < 4:
            state = c_match_next
        else:
            out = outBuf.require(t)
            ip, op, t = copy(inBuf, out, ip, op, t, t)
            state = c_first_literal_run
    while True:
        if_block = False
        # emulate c switch structure by sequences of if statment
        if state == c_top_loop:
            t = inBuf[ip]
            ip = ip + 1
            if t >= 16:
                state = c_match
                continue
            if t == 0:
                while inBuf[ip] == 0:
                    t, ip = t+255, ip+1
                t = t + 15 + inBuf[ip]
                ip = ip + 1
            t = t + 3
            out = outBuf.require(t)
            ip, op, t = copy(inBuf, out, ip, op, t, t)
            state = c_first_literal_run
        if state == c_first_literal_run:
            t = inBuf[ip]
            ip = ip + 1
            if t >= 16:
                state = c_match
                continue
            m_pos = op - 0x801 - (t >> 2) - (inBuf[ip] << 2)
            ip = ip + 1
            out = outBuf.require(3)
            _, op, _ = copy(out, out, m_pos, op, 0, 3)
            state = c_match_done
            continue
        if state == c_match:
            if t >= 64:
                m_pos = op - 1 - ((t >> 2) & 7) - (inBuf[ip] << 3)
                ip = ip + 1
                t = (t >> 5) - 1
                state = c_copy_match
                continue
            elif t >= 32:
                t = t & 31
                if t == 0:
                    while inBuf[ip] == 0:
                        t, ip = t+255, ip+1
                    t = t + 31 + inBuf[ip]
                    ip = ip + 1
                m_pos = op - 1 - ((inBuf[ip] + (inBuf[ip + 1] << 8)) >> 2)
                ip = ip + 2
            elif t >= 16:
                m_pos = op - ((t & 8) << 11)
                t = t & 7
                if t == 0:
                    while inBuf[ip] == 0:
                        t, ip = t+255, ip+1
                    t = t + 7 + inBuf[ip]
                    ip = ip + 1
                m_pos = m_pos - ((inBuf[ip] + (inBuf[ip + 1] << 8)) >> 2)
                ip = ip + 2
                if m_pos == op:
                    break
                m_pos = m_pos - 0x4000
            else:
                m_pos = op - 1 - (t >> 2) - (inBuf[ip] << 2);
                ip = ip + 1
                out = outBuf.require(2)
                _, op, _ = copy(out, out, m_pos, op, 0, 2)
                state = c_match_done
                continue
            if t >= 6 and (op - m_pos) >= 4:
                if_block = True
                t += 2
                out = outBuf.require(t)
                m_pos, op, t = copy(out, out, m_pos, op, t, t)
            state = c_copy_match
        if state == c_copy_match:
            if not if_block:
                t += 2
                out = outBuf.require(t)
                m_pos, op, t = copy(out, out, m_pos, op, t, t)
            state = c_match_done
        if state == c_match_done:
            t = inBuf[ip - 2] & 3
            if t == 0:
                state = c_top_loop
                continue
            state = c_match_next
        if state == c_match_next:
            out = outBuf.require(1)
            ip, op, _ = copy(inBuf, out, ip, op, 0, 1)
            if t > 1:
                out = outBuf.require(1)
                ip, op, _ = copy(inBuf, out, ip, op, 0, 1)
            if t > 2:
                out = outBuf.require(1)
                ip, op, _ = copy(inBuf, out, ip, op, 0, 1)
            t = inBuf[ip]
            ip += 1
            state = c_match
    return bytes(outBuf.pack(op))

def lzo_decompress(input, initSize=16000, blockSize=1308672):
    output = FlexBuffer()
    output.alloc(initSize, blockSize)
    return _decompress(bytearray(input), output)

#########
# For RIPEMD128
#
def f(j, x, y, z):
    assert(0 <= j < 64)
    return ((x ^ y ^ z)                   if j<16 else
            ((x & y) | (z & ~x))          if j<32 else
            ((x | (0xffffffff & ~y)) ^ z) if j<48 else
            ((x & z) | (y & ~z))
           )
def K(j):
    assert(0 <= j < 64)
    return (0x00000000 if j<16 else
            0x5a827999 if j<32 else
            0x6ed9eba1 if j<48 else
            0x8f1bbcdc
           )
def Kp(j):
    assert(0 <= j < 64)
    return (0x50a28be6 if j<16 else
            0x5c4dd124 if j<32 else
            0x6d703ef3 if j<48 else
            0x00000000
           )
def padandsplit(message):
    """
    returns a two-dimensional array X[i][j] of 32-bit integers, where j ranges
    from 0 to 16.
    First pads the message to length in bytes is congruent to 56 (mod 64), 
    by first adding a byte 0x80, and then padding with 0x00 bytes until the
    message length is congruent to 56 (mod 64). Then adds the little-endian
    64-bit representation of the original length. Finally, splits the result
    up into 64-byte blocks, which are further parsed as 32-bit integers.
    """
    origlen = len(message)
    padlength = 64 - ((origlen - 56) % 64) #minimum padding is 1!
    message += b"\x80"
    message += b"\x00" * (padlength - 1)
    message += pack("<Q", origlen*8)
    assert(len(message) % 64 == 0)
    return [
             [
               unpack("<L", message[i+j:i+j+4])[0]
               for j in range(0, 64, 4)
             ]
             for i in range(0, len(message), 64)
           ]
def add(*args):
    return sum(args) & 0xffffffff
def rol(s,x):
    assert(s < 32)
    return (x << s | x >> (32-s)) & 0xffffffff
r =  [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
       7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
       3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
       1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2]
rp = [ 5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
       6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
      15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
       8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14]
s =  [11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
       7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
      11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
      11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12]
sp = [ 8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
       9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
       9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
      15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8]
def ripemd128(message):
    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476
    X = padandsplit(message)
    for i in range(len(X)):
        (A,B,C,D) = (h0,h1,h2,h3)
        (Ap,Bp,Cp,Dp) = (h0,h1,h2,h3)
        for j in range(64):
            T = rol(s[j], add(A, f(j,B,C,D), X[i][r[j]], K(j)))
            (A,D,C,B) = (D,C,B,T)
            T = rol(sp[j], add(Ap, f(63-j,Bp,Cp,Dp), X[i][rp[j]], Kp(j)))
            (Ap,Dp,Cp,Bp) = (Dp,Cp,Bp,T)
        T = add(h1,C,Dp)
        h1 = add(h2,D,Ap)
        h2 = add(h3,A,Bp)
        h3 = add(h0,B,Cp)
        h0 = T
    return pack("<LLLL",h0,h1,h2,h3)
def hexstr(bstr):
    return "".join("{0:02x}".format(b) for b in bstr)
#########
# For Salsa20
#
little_u64 = Struct( "<Q" )      #    little-endian 64-bit unsigned.
                                 #    Unpacks to a tuple of one element!
little16_i32 = Struct( "<16i" )  # 16 little-endian 32-bit signed ints.
little4_i32 = Struct( "<4i" )    #  4 little-endian 32-bit signed ints.
little2_i32 = Struct( "<2i" )    #  2 little-endian 32-bit signed ints.
class Salsa20(object):
    def __init__(self, key=None, IV=None, rounds=20 ):
        self._lastChunk64 = True
        self._IVbitlen = 64             # must be 64 bits
        self.ctx = [ 0 ] * 16
        if key:
            self.setKey(key)
        if IV:
            self.setIV(IV)
        self.setRounds(rounds)
    def setKey(self, key):
        assert type(key) == bytes
        ctx = self.ctx
        if len( key ) == 32:  # recommended
            constants = b"expand 32-byte k"
            ctx[ 1],ctx[ 2],ctx[ 3],ctx[ 4] = little4_i32.unpack(key[0:16])
            ctx[11],ctx[12],ctx[13],ctx[14] = little4_i32.unpack(key[16:32])
        elif len( key ) == 16:
            constants = b"expand 16-byte k"
            ctx[ 1],ctx[ 2],ctx[ 3],ctx[ 4] = little4_i32.unpack(key[0:16])
            ctx[11],ctx[12],ctx[13],ctx[14] = little4_i32.unpack(key[0:16])
        else:
            raise Exception( "key length isn't 32 or 16 bytes." )
        ctx[0],ctx[5],ctx[10],ctx[15] = little4_i32.unpack( constants )
    def setIV(self, IV):
        assert type(IV) == bytes
        assert len(IV)*8 == 64, 'nonce (IV) not 64 bits'
        self.IV = IV
        ctx=self.ctx
        ctx[ 6],ctx[ 7] = little2_i32.unpack( IV )
        ctx[ 8],ctx[ 9] = 0, 0  # Reset the block counter.
    setNonce = setIV            # support an alternate name
    def setCounter( self, counter ):
        assert( type(counter) in integer_types )
        assert( 0 <= counter < 1<<64 ), "counter < 0 or >= 2**64"
        ctx = self.ctx
        ctx[ 8],ctx[ 9] = little2_i32.unpack( little_u64.pack( counter ) )
    def getCounter( self ):
        return little_u64.unpack( little2_i32.pack( *self.ctx[ 8:10 ] ) ) [0]
    def setRounds(self, rounds, testing=False ):
        assert testing or rounds in [8, 12, 20], 'rounds must be 8, 12, 20'
        self.rounds = rounds
    def encryptBytes(self, data):
        assert type(data) == bytes, 'data must be byte string'
        assert self._lastChunk64, 'previous chunk not multiple of 64 bytes'
        lendata = len(data)
        munged = bytearray(lendata)
        for i in range( 0, lendata, 64 ):
            h = salsa20_wordtobyte( self.ctx, self.rounds, checkRounds=False )
            self.setCounter( ( self.getCounter() + 1 ) % 2**64 )
            # Stopping at 2^70 bytes per nonce is user's responsibility.
            for j in range( min( 64, lendata - i ) ):
                if python3:
                    munged[ i+j ] = data[ i+j ] ^ h[j]
                else:
                    munged[ i+j ] = ord(data[ i+j ]) ^ ord(h[j])
        self._lastChunk64 = not lendata % 64
        return bytes(munged)
    decryptBytes = encryptBytes # encrypt and decrypt use same function
def salsa20_wordtobyte( input, nRounds=20, checkRounds=True ):
    """ Do nRounds Salsa20 rounds on a copy of 
            input: list or tuple of 16 ints treated as little-endian unsigneds.
        Returns a 64-byte string.
        """
    assert( type(input) in ( list, tuple )  and  len(input) == 16 )
    assert( not(checkRounds) or ( nRounds in [ 8, 12, 20 ] ) )
    x = list( input )
    def XOR( a, b ):  return a ^ b
    ROTATE = rot32
    PLUS   = add32
    for i in range( nRounds // 2 ):
        # These ...XOR...ROTATE...PLUS... lines are from ecrypt-linux.c
        x[ 4] = XOR(x[ 4],ROTATE(PLUS(x[ 0],x[12]), 7))
        x[ 8] = XOR(x[ 8],ROTATE(PLUS(x[ 4],x[ 0]), 9))
        x[12] = XOR(x[12],ROTATE(PLUS(x[ 8],x[ 4]),13))
        x[ 0] = XOR(x[ 0],ROTATE(PLUS(x[12],x[ 8]),18))
        x[ 9] = XOR(x[ 9],ROTATE(PLUS(x[ 5],x[ 1]), 7))
        x[13] = XOR(x[13],ROTATE(PLUS(x[ 9],x[ 5]), 9))
        x[ 1] = XOR(x[ 1],ROTATE(PLUS(x[13],x[ 9]),13))
        x[ 5] = XOR(x[ 5],ROTATE(PLUS(x[ 1],x[13]),18))
        x[14] = XOR(x[14],ROTATE(PLUS(x[10],x[ 6]), 7))
        x[ 2] = XOR(x[ 2],ROTATE(PLUS(x[14],x[10]), 9))
        x[ 6] = XOR(x[ 6],ROTATE(PLUS(x[ 2],x[14]),13))
        x[10] = XOR(x[10],ROTATE(PLUS(x[ 6],x[ 2]),18))
        x[ 3] = XOR(x[ 3],ROTATE(PLUS(x[15],x[11]), 7))
        x[ 7] = XOR(x[ 7],ROTATE(PLUS(x[ 3],x[15]), 9))
        x[11] = XOR(x[11],ROTATE(PLUS(x[ 7],x[ 3]),13))
        x[15] = XOR(x[15],ROTATE(PLUS(x[11],x[ 7]),18))

        x[ 1] = XOR(x[ 1],ROTATE(PLUS(x[ 0],x[ 3]), 7))
        x[ 2] = XOR(x[ 2],ROTATE(PLUS(x[ 1],x[ 0]), 9))
        x[ 3] = XOR(x[ 3],ROTATE(PLUS(x[ 2],x[ 1]),13))
        x[ 0] = XOR(x[ 0],ROTATE(PLUS(x[ 3],x[ 2]),18))
        x[ 6] = XOR(x[ 6],ROTATE(PLUS(x[ 5],x[ 4]), 7))
        x[ 7] = XOR(x[ 7],ROTATE(PLUS(x[ 6],x[ 5]), 9))
        x[ 4] = XOR(x[ 4],ROTATE(PLUS(x[ 7],x[ 6]),13))
        x[ 5] = XOR(x[ 5],ROTATE(PLUS(x[ 4],x[ 7]),18))
        x[11] = XOR(x[11],ROTATE(PLUS(x[10],x[ 9]), 7))
        x[ 8] = XOR(x[ 8],ROTATE(PLUS(x[11],x[10]), 9))
        x[ 9] = XOR(x[ 9],ROTATE(PLUS(x[ 8],x[11]),13))
        x[10] = XOR(x[10],ROTATE(PLUS(x[ 9],x[ 8]),18))
        x[12] = XOR(x[12],ROTATE(PLUS(x[15],x[14]), 7))
        x[13] = XOR(x[13],ROTATE(PLUS(x[12],x[15]), 9))
        x[14] = XOR(x[14],ROTATE(PLUS(x[13],x[12]),13))
        x[15] = XOR(x[15],ROTATE(PLUS(x[14],x[13]),18))
    for i in range( len( input ) ):
        x[i] = PLUS( x[i], input[i] )
    return little16_i32.pack( *x )
def trunc32( w ):
    "extract bottom 32 bits to a 32-bit word"
    w = int( ( w & 0x7fffFFFF ) | -( w & 0x80000000 ) )
    assert type(w) == int
    return w
def add32( a, b ):
    "add two 32-bit word and keep retval a 32-bit word by discarding carry"
    lo = ( a & 0xFFFF ) + ( b & 0xFFFF )
    hi = ( a >> 16 ) + ( b >> 16 ) + ( lo >> 16 )
    return ( -(hi & 0x8000) | ( hi & 0x7FFF ) ) << 16 | ( lo & 0xFFFF )
def rot32( w, nLeft ):
    "left rotate 32-bit word and keep retval a 32-bit word"
    nLeft &= 31  # which makes nLeft >= 0
    if nLeft == 0:
        return w
    # Note: now 1 <= nLeft <= 31.
    #     RRRsLLLLLL   There are nLeft RRR's, (31-nLeft) LLLLLL's,
    # =>  sLLLLLLRRR   and one s which becomes the sign bit.
    RRR = ( ( ( w >> 1 ) & 0x7fffFFFF ) >> ( 31 - nLeft ) )
    sLLLLLL = -( (1<<(31-nLeft)) & w ) | (0x7fffFFFF>>nLeft) & w
    return RRR | ( sLLLLLL << nLeft )
def _unescape_entities(text):
    ' unescape offending tags < > " & '
    text = text.replace(b'&lt;', b'<')
    text = text.replace(b'&gt;', b'>')
    text = text.replace(b'&quot;', b'"')
    text = text.replace(b'&amp;', b'&')
    return text
def _fast_decrypt(data, key):
    b = bytearray(data)
    key = bytearray(key)
    previous = 0x36
    for i in range(len(b)):
        t = (b[i] >> 4 | b[i] << 4) & 0xff
        t = t ^ previous ^ (i & 0xff) ^ key[i % len(key)]
        previous, b[i] = b[i], t
    return bytes(b)
def _mdx_decrypt(comp_block):
    key = ripemd128(comp_block[4:8] + pack(b'<L', 0x3695))
    return comp_block[0:8] + _fast_decrypt(comp_block[8:], key)
def _salsa_decrypt(ciphertext, encrypt_key):
    s20 = Salsa20(key=encrypt_key, IV=b"\x00" * 8, rounds=8)
    return s20.encryptBytes(ciphertext)
def _decrypt_regcode_by_deviceid(reg_code, deviceid):
    deviceid_digest = ripemd128(deviceid)
    s20 = Salsa20(key=deviceid_digest, IV=b"\x00" * 8, rounds=8)
    encrypt_key = s20.encryptBytes(reg_code)
    return encrypt_key
def _decrypt_regcode_by_email(reg_code, email):
    email_digest = ripemd128(email.decode().encode('utf-16-le'))
    s20 = Salsa20(key=email_digest, IV=b"\x00" * 8, rounds=8)
    encrypt_key = s20.encryptBytes(reg_code)
    return encrypt_key

#########
# Octopus mdict object classes
#
PLAIN_MAGIC = b'\x00\x00\x00\x00'
LZO_MAGIC = b'\x01\x00\x00\x00'
ZLIB_MAGIC = b'\x02\x00\x00\x00'

def decompress(block_type, block_data, decompressed_size=0):
    if block_type == PLAIN_MAGIC: # no compression
        return block_data
    elif block_type == LZO_MAGIC: # LZO compressed
        return lzo_decompress(block_data, decompressed_size)
    elif block_type == ZLIB_MAGIC: # zlib compressed
        return zlib.decompress(block_data)

class MDict(object):
    """
    Base class which reads in header and key block.
    It has no public methods and serves only as code sharing base class.
    """
    def __init__(self, fname, encoding='', passcode=None):
        self._fname    = fname
        self._encoding = encoding.upper()
        self._passcode = passcode
        self.header    = self._read_header()
        try:
            self._key_list = self._read_keys()
        except:
            print("Try Brute Force on Encrypted Key Blocks")
            self._key_list = self._read_keys_brutal()
    def __len__(self):
        return self._num_entries
    def __iter__(self):
        return self.keys()
    def keys(self):
        return (key_value for key_id, key_value in self._key_list)
    def items(self):
        raise NotImplementedError
    def _read_number(self, f):
        return unpack(self._number_format, f.read(self._number_width))[0]
    def _parse_header(self, header):
        """
        extract attributes from <Dict attr="value" ... >
        """
        taglist = re.findall(b'(\w+)="(.*?)"', header, re.DOTALL)
        return {key:_unescape_entities(value) for key, value in taglist}
    def get_records(self):
        """
        Return a generator for key and value of each record
        key is from self._key_list, value is decrypted/decompressed record body
        """
        with open(self._fname, 'rb') as f:
            f.seek(self._record_block_offset)
            # metadata from header
            num_record_blocks      = self._read_number(f)
            num_entries            = self._read_number(f)
            record_block_info_size = self._read_number(f)
            record_block_size      = self._read_number(f)
            assert(num_entries == self._num_entries)
            # metadata of each record
            record_block_info_list = []
            size_counter = 0
            for i in range(num_record_blocks):
                compressed_size        =  self._read_number(f)
                decompressed_size      =  self._read_number(f)
                record_block_info_list += [(compressed_size, decompressed_size)]
                size_counter           += self._number_width * 2
            assert(size_counter == record_block_info_size)
            # scan each record
            offset = i = size_counter = 0
            for compressed_size, decompressed_size in record_block_info_list:
                current_pos = f.tell()
                # the whole record: read `compressed_size` bytes for compressed data
                record_block_compressed = f.read(compressed_size)
                # first 4 bytes: compression type
                # next 4 bytes: adler32 checksum of decompressed record block
                # the rest: record data
                record_block_type = record_block_compressed[:4]
                adler32 = unpack('>I', record_block_compressed[4:8])[0]
                record_block = decompress(record_block_type, record_block_compressed[8:], decompressed_size)
                compress_type = {PLAIN_MAGIC:0, LZO_MAGIC:1, ZLIB_MAGIC:2}[record_block_type]
                assert(adler32 == zlib.adler32(record_block) & 0xffffffff) # adler32 is signed
                assert(len(record_block) == decompressed_size)
                # split record block according to the offset info from key block
                while i < len(self._key_list):
                    record_start, key_text = self._key_list[i]
                    # reach the end of current record block
                    if record_start - offset >= decompressed_size:
                        break
                    # record end index
                    if i < len(self._key_list) - 1:
                        record_end = self._key_list[i + 1][0]
                    else:
                        record_end = decompressed_size + offset
                    i += 1
                    yield {
                        'file_pos':          current_pos
                       ,'compressed_size':   compressed_size
                       ,'decompressed_size': decompressed_size
                       ,'record_block_type': compress_type
                       ,'record_start':      record_start
                       ,'key_text':          key_text
                       ,'offset':            offset
                       ,'data':              record_block[record_start - offset:record_end - offset]
                       ,'record_end':        record_end
                    }
                offset += decompressed_size
                size_counter += compressed_size
            # verify how much read matches what is specified in header
            assert(size_counter == record_block_size)
    def _decode_key_block_info(self, key_block_info_compressed):
        if self._version >= 2:
            # version>=2 must use zlib compression
            assert(key_block_info_compressed[:4] == ZLIB_MAGIC)
            # decrypt if needed, then decompress
            if self._encrypt & 0x02:
                key_block_info_compressed = _mdx_decrypt(key_block_info_compressed)
            key_block_info = decompress(ZLIB_MAGIC, key_block_info_compressed[8:])
            # verify adler checksum
            adler32 = unpack('>I', key_block_info_compressed[4:8])[0]
            assert(adler32 == zlib.adler32(key_block_info) & 0xffffffff)
        else:
            # no compression
            key_block_info = key_block_info_compressed
        # decode
        key_block_info_list = []
        num_entries = i = 0
        if self._version >= 2:
            byte_format, byte_width, text_term = '>H', 2, 1
        else:
            byte_format, byte_width, text_term = '>B', 1, 0
        while i < len(key_block_info):
            # number of entries in current key block
            num_entries += unpack(self._number_format, key_block_info[i:i+self._number_width])[0]
            i += self._number_width
            # text head size
            text_head_size = unpack(byte_format, key_block_info[i:i+byte_width])[0]
            i += byte_width
            # text head
            if self._encoding != 'UTF-16':
                i += text_head_size + text_term
            else:
                i += (text_head_size + text_term) * 2
            # text tail size
            text_tail_size = unpack(byte_format, key_block_info[i:i+byte_width])[0]
            i += byte_width
            # text tail
            if self._encoding != 'UTF-16':
                i += text_tail_size + text_term
            else:
                i += (text_tail_size + text_term) * 2
            # key block compressed size
            key_block_compressed_size = unpack(self._number_format, key_block_info[i:i+self._number_width])[0]
            i += self._number_width
            # key block decompressed size
            key_block_decompressed_size = unpack(self._number_format, key_block_info[i:i+self._number_width])[0]
            i += self._number_width
            key_block_info_list += [(key_block_compressed_size, key_block_decompressed_size)]
        assert(num_entries == self._num_entries)
        return key_block_info_list
    def _decode_key_block(self, key_block_compressed, key_block_info_list):
        key_list = []
        i = 0
        for compressed_size, decompressed_size in key_block_info_list:
            start = i
            i = end = i + compressed_size
            # 4 bytes : compression type
            key_block_type = key_block_compressed[start:start+4]
            # 4 bytes : adler checksum of decompressed key block
            adler32 = unpack('>I', key_block_compressed[start+4:start+8])[0]
            key_block = decompress(key_block_type, key_block_compressed[start+8:end], decompressed_size)
            # extract one single key block into a key list
            key_list += self._split_key_block(key_block)
            # notice that adler32 returns signed value
            assert(adler32 == zlib.adler32(key_block) & 0xffffffff)
        return key_list
    def _split_key_block(self, key_block):
        key_list = []
        key_start_index = 0
        while key_start_index < len(key_block):
            # the corresponding record's offset in record block
            key_id = unpack(self._number_format,
                            key_block[key_start_index:key_start_index+self._number_width]
                           )[0]
            # key text ends with '\x00'
            if self._encoding == 'UTF-16':
                delimiter, width = b'\x00\x00', 2
            else:
                delimiter, width = b'\x00', 1
            i = key_start_index + self._number_width
            while i < len(key_block):
                if key_block[i:i + width] == delimiter:
                    key_end_index = i
                    break
                i += width
            key_text = key_block[key_start_index + self._number_width:key_end_index]\
                       .decode(self._encoding, errors='ignore').encode('utf-8').strip()
            key_start_index = key_end_index + width
            key_list += [(key_id, key_text)]
        return key_list
    def _read_header(self):
        with open(self._fname, 'rb') as f:
            # number of bytes of header text
            header_bytes_size = unpack('>I', f.read(4))[0]
            header_bytes = f.read(header_bytes_size)
            # 4 bytes: adler32 checksum of header, in little endian
            adler32 = unpack('<I', f.read(4))[0]
            assert(adler32 == zlib.adler32(header_bytes) & 0xffffffff)
            # mark down key block offset
            self._key_block_offset = f.tell()
        # header text in utf-16 encoding ending with '\x00\x00'
        header_text = header_bytes[:-2].decode('utf-16').encode('utf-8')
        header_tag = self._parse_header(header_text)
        if not self._encoding:
            encoding = header_tag[b'Encoding']
            if sys.version_info >= (3,):
                encoding = encoding.decode('utf-8')
            # GB18030 is superset of  GBK & GB2312
            if encoding in ['GBK', 'GB2312']:
                encoding = 'GB18030'
            self._encoding = encoding
        # read title and description
        self._title = header_tag[b'Title'].decode('utf-8') if b'Title' in header_tag else ''
        self._description = header_tag[b'Description'].decode('utf-8') if b'Description' in header_tag else ''
        # encryption flag
        #   0x00 - no encryption
        #   0x01 - encrypt record block
        #   0x02 - encrypt key info block
        if b'Encrypted' not in header_tag or header_tag[b'Encrypted'] == b'No':
            self._encrypt = 0
        elif header_tag[b'Encrypted'] == b'Yes':
            self._encrypt = 1
        else:
            self._encrypt = int(header_tag[b'Encrypted'])
        # stylesheet attribute if present takes form of:
        #   style_number # 1-255
        #   style_begin # or ''
        #   style_end # or ''
        # store stylesheet in dict in the form of
        # {'number' : ('style_begin', 'style_end')}
        self._stylesheet = {}
        if header_tag.get('StyleSheet'):
            lines = header_tag['StyleSheet'].splitlines()
            for i in range(0, len(lines), 3):
                self._stylesheet[lines[i]] = (lines[i + 1], lines[i + 2])
        # before version 2.0, number is 4 bytes integer
        # version 2.0 and above uses 8 bytes
        self._version = float(header_tag[b'GeneratedByEngineVersion'])
        if self._version < 2.0:
            self._number_width, self._number_format = 4, '>I'
        else:
            self._number_width, self._number_format = 8, '>Q'
        return header_tag
    def _read_keys(self):
        with open(self._fname, 'rb') as f:
            f.seek(self._key_block_offset)
            # the following numbers could be encrypted
            num_bytes = (8*5) if self._version >= 2.0 else (4*4)
            block = f.read(num_bytes)
            if self._encrypt & 1:
                if self._passcode is None:
                    raise RuntimeError('user identification is needed to read encrypted file')
                regcode, userid = self._passcode
                if isinstance(userid, unicode):
                    userid = userid.encode('utf8')
                if self.header[b'RegisterBy'] == b'EMail':
                    encrypted_key = _decrypt_regcode_by_email(regcode, userid)
                else:
                    encrypted_key = _decrypt_regcode_by_deviceid(regcode, userid)
                block = _salsa_decrypt(block, encrypted_key)
            # decode this block
            sf = BytesIO(block)
            num_key_blocks = self._read_number(sf)
            self._num_entries = self._read_number(sf)
            # number of bytes of key block info after decompression
            if self._version >= 2.0:
                _ = self._read_number(sf) # key_block_info_decomp_size, unused here
            # number of bytes of key block info
            key_block_info_size = self._read_number(sf)
            # number of bytes of key block
            key_block_size = self._read_number(sf)
            # 4 bytes: adler checksum of previous 5 numbers
            if self._version >= 2.0:
                adler32 = unpack('>I', f.read(4))[0]
                assert adler32 == (zlib.adler32(block) & 0xffffffff)
            # read key block info, which indicates key block's compressed and decompressed size
            key_block_info = f.read(key_block_info_size)
            key_block_info_list = self._decode_key_block_info(key_block_info)
            assert(num_key_blocks == len(key_block_info_list))
            # read and decompress key block
            key_block_compressed = f.read(key_block_size)
            key_list = self._decode_key_block(key_block_compressed, key_block_info_list)
            self._record_block_offset = f.tell()
        return key_list
    def _read_keys_brutal(self):
        with open(self._fname, 'rb') as f:
            f.seek(self._key_block_offset)
            # the following numbers could be encrypted, disregard them!
            if self._version >= 2.0:
                num_bytes, key_block_type = (8*5+4), ZLIB_MAGIC
            else:
                num_bytes, key_block_type = (4*4), LZO_MAGIC
            block = f.read(num_bytes)
            # key block info:
            # - 4 bytes '\x02\x00\x00\x00'
            # - 4 bytes adler32 checksum
            # - a number of bytes
            # - 4 bytes '\x02\x00\x00\x00' marks the beginning of key block
            key_block_info = f.read(8)
            if self._version >= 2.0:
                assert key_block_info[:4] == ZLIB_MAGIC
            while True:
                fpos = f.tell()
                t = f.read(1024)
                index = t.find(key_block_type)
                if index != -1:
                    key_block_info += t[:index]
                    f.seek(fpos + index)
                    break
                else:
                    key_block_info += t
            key_block_info_list = self._decode_key_block_info(key_block_info)
            key_block_size = sum(list(zip(*key_block_info_list))[0])
            # read and decompress key block
            key_block_compressed = f.read(key_block_size)
            key_list = self._decode_key_block(key_block_compressed, key_block_info_list)
            self._record_block_offset = f.tell()
        self._num_entries = len(key_list)
        return key_list
    def get_index(self):
        index_dict_list = [] # list of dict, each one is index to one record
        for record_dict in self.get_records():
            del record_dict['data']
            index_dict_list.append(index_dict)
        return index_dict_list

class MDD(MDict):
    """
    MDict resource file format (*.MDD) reader.
    >>> mdd = MDD('example.mdd')
    >>> len(mdd)
    208
    >>> for filename,content in mdd.items():
    ... print filename, content[:10]
    """
    def __init__(self, fname, passcode=None):
        MDict.__init__(self, fname, encoding='UTF-16', passcode=passcode)
    def items(self):
        """
        Return a generator which in turn produce tuples of (filename, blob),
        both in bytestring
        """
        for record_dict in self.get_records():
            filename = record_dict['key_text'].decode('utf-8')
            blob = record_dict['data']
            yield filename, blob

class MDX(MDict):
    """
    MDict dictionary file format (*.MDD) reader.
    >>> mdx = MDX('example.mdx')
    >>> len(mdx)
    42481
    >>> for key,value in mdx.items():
    ... print key, value[:10]
    """
    def __init__(self, fname, encoding='', substyle=False, passcode=None):
        MDict.__init__(self, fname, encoding, passcode)
        self._substyle = substyle
    def _substitute_stylesheet(self, txt):
        'Replace style with loaded stylesheet'
        txt_list = re.split('`\d+`', txt)
        txt_tag = re.findall('`\d+`', txt)
        txt_styled = txt_list[0]
        for j, p in enumerate(txt_list[1:]):
            style = self._stylesheet[txt_tag[j][1:-1]]
            if p and p[-1] == b'\n':
                txt_styled = txt_styled + style[0] + p.rstrip() + style[1] + b'\r\n'
            else:
                txt_styled = txt_styled + style[0] + p + style[1]
        return txt_styled
    def items(self):
        """
        Return a generator which in turn produce tuples in the form of (title, text),
        both in unicode string
        """
        for record_dict in self.get_records():
            title = record_dict['key_text']
            text  = record_dict['data'] \
                    .decode(self._encoding, errors='ignore') \
                    .strip(u'\x00') \
                    .encode('utf-8')
            # substitute stylesheet if required
            if self._substyle and self._stylesheet:
                text = self._substitute_stylesheet(text)
            yield title, text
    def get_index(self):
        index_dict_list = super(MDX,self).get_index()
        return {
            "index_dict_list": index_dict_list
           ,"meta": {
                'encoding':    self._encoding
               ,'stylesheet':  json.dumps(self._stylesheet)
               ,'title':       self._title
               ,'description': self._description
            }
        }
