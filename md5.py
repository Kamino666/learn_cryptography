# -*- coding: utf-8 -*-
#
# coded by Kamino, 2022, <kamino@cuc.edu.cn>
#
# It is a simple implementation of the MD5 algorithm in Python3.10.
# Distributed freely with attribution.
# This code is based on rfc1321.
# It is not recommended to use this code in practice. For security
# and performance, please use hashlib.
#
import bitarray as ba
from bitarray.util import ba2int, int2ba, hex2ba
from typing import Union
import hashlib  # Only for evaluation


class MD5:
    # Constants
    T = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ]
    # index of message word(32b)
    MI = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12],
        [5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2],
        [0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9],
    ]
    # shift numbers
    S = [
        [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, ],
        [5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, ],
        [4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, ],
        [6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, ]
    ]
    # initial numbers of the 4 register
    INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    # functions
    F = lambda x, y, z: (x & y) | ((~x) & z)
    G = lambda x, y, z: (x & z) | (y & (~z))
    H = lambda x, y, z: x ^ y ^ z
    I = lambda x, y, z: y ^ (x | (~z))

    @classmethod
    def hash(cls, src: Union[bytes, str]) -> str:
        processed_blocks = cls._preprocess(src)
        res = cls.md5_core(processed_blocks)
        return res.tobytes().hex()

    @classmethod
    def reverse_endianness(cls, x: ba.bitarray) -> ba.bitarray:
        """
        Change the endianness of x.
        example when x is a number of 264:
        00 00 00 00 00 00 01 08 -> 08 01 00 00 00 00 00 00
        :param x:
        :return:
        """
        _x = x.tobytes().hex('_').split('_')
        _x.reverse()
        return hex2ba("".join(_x))

    @classmethod
    def _preprocess(cls, src: Union[bytes, str]):
        """
        Make blocks of 512bit/64B and pad to the standard format
        :param src:
        :return:
        """
        src = src.encode() if type(src) is str else src
        length = len(src)
        # make blocks
        blocks = []
        for i in range(0, len(src), 64):
            block = ba.bitarray()
            block.frombytes(src[i: i + 64])
            blocks.append(block)

        # pad 100...0
        if len(blocks) == 0:  # prevent empty input
            blocks.append(ba.bitarray())
        if len(blocks[-1]) < 448:  # less than 488bit: pad 100...0 until 488
            blocks[-1].extend("1" + "0" * (448 - len(blocks[-1]) - 1))
        elif len(blocks[-1]) < 512:  # greater than or equal to 488：pad to 512，than add a new block of 448*0
            blocks[-1].extend("1" + "0" * (512 - len(blocks[-1]) - 1))
            blocks.append(ba.bitarray("0" * 448))
        else:  # equal to 512，directly add a padded block of 488
            blocks.append(ba.bitarray("1" + "0" * 447))

        # add the 64bit/8B length to the end
        # NOTICE! low-order bytes are placed earlier
        # example when length is 264:
        # 00 00 00 00 00 00 01 08 -> 08 01 00 00 00 00 00 00
        blocks[-1] += cls.reverse_endianness(int2ba(length * 8, 64))
        return blocks

    @classmethod
    def _cyclic_left_shift32(cls, x, n):
        """Cyclic left shift n bit of a 32bit word"""
        # & 0xffffffff means (mod 2^32)
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    @classmethod
    def _step(cls, a, b, c, d, mi, tj, s, func):
        """process a step."""
        # & 0xffffffff means (mod 2^32)
        e1 = (func(b, c, d) + a + mi + tj) & 0xffffffff
        e2 = (b + cls._cyclic_left_shift32(e1, s)) & 0xffffffff
        return d, e2, b, c

    @classmethod
    def md5_core(cls, blocks):
        """
        Core function of MD5 algorithm.
        Notice the to reverse endianness!
        """
        func_list = (cls.F, cls.G, cls.H, cls.I)
        a, b, c, d = cls.INIT
        # Block
        for block in blocks:
            aa, bb, cc, dd = a, b, c, d
            # Round
            for round_num in range(4):
                # Step
                for step_num in range(16):
                    block_bytes = block[cls.MI[round_num][step_num] * 32:cls.MI[round_num][step_num] * 32 + 32]
                    aa, bb, cc, dd = cls._step(
                        aa, bb, cc, dd,
                        ba2int(cls.reverse_endianness(block_bytes)),
                        cls.T[round_num * 16 + step_num],
                        cls.S[round_num][step_num],
                        func_list[round_num]
                    )
            a = (a + aa) & 0xffffffff
            b = (b + bb) & 0xffffffff
            c = (c + cc) & 0xffffffff
            d = (d + dd) & 0xffffffff
        return cls.reverse_endianness(int2ba(a, 32)) + cls.reverse_endianness(int2ba(b, 32)) + \
               cls.reverse_endianness(int2ba(c, 32)) + cls.reverse_endianness(int2ba(d, 32))


test_suite = {
    "": "d41d8cd98f00b204e9800998ecf8427e",
    "a": "0cc175b9c0f1b6a831c399e269772661",
    "abc": "900150983cd24fb0d6963f7d28e17f72",
    "message digest": "f96b697d7cb7938d525a2f31aaf161d0",
    "abcdefghijklmnopqrstuvwxyz": "c3fcd3d76192e4007dfb496cca67e13b",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "d174ab98d277d9f5a5611c2c9f419d9f",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "57edf4a22be3c955ac49da2e2107b67a"
}

for k, v in test_suite.items():
    # my_res = md5(md5_pad(str2bin(k))).tobytes().hex()
    my_res = MD5.hash(k)
    hashlib_res = hashlib.md5(k.encode()).hexdigest()
    truth_res = v
    print(f"For message: \"{k}\"")
    print(f"My: {my_res}\nHashlib: {hashlib_res}\nTruth: {truth_res}")
    print(f"\033[1;33;40m {my_res == hashlib_res == truth_res} \033[0m")
