# -*- coding: utf-8 -*-
#
# coded by Liu Zihao, 2022, <kamino@cuc.edu.cn>
#
# It is a simple implementation of the MD5 algorithm in Python3.10.
# Distributed freely with attribution.
# This code is based on FIPS PUB 180-1 SECURE HASH STANDARD.
# It is not recommended to use this code in practice. For security
# and performance, please use hashlib.
#
import bitarray as ba
from bitarray.util import ba2int, int2ba, hex2ba
from typing import Union
import hashlib  # Only for evaluation


class SHA1:
    # Constants
    K = [0x5A827999] * 20 + [0x6ED9EBA1] * 20 + [0x8F1BBCDC] * 20 + [0xCA62C1D6] * 20
    # initial numbers of the 5 register
    INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    # functions
    F1 = lambda x, y, z: (x & y) | ((~x) & z)
    F2 = lambda x, y, z: x ^ y ^ z
    F3 = lambda x, y, z: (x & y) | (x & z) | (y & z)
    F4 = lambda x, y, z: x ^ y ^ z

    @classmethod
    def hash(cls, src: Union[bytes, str]) -> str:
        processed_blocks = cls._preprocess(src)
        res = cls.sha1_core(processed_blocks)
        return res.tobytes().hex()

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

        blocks[-1] += int2ba(length * 8, 64)
        return blocks

    @classmethod
    def _cyclic_left_shift32(cls, x, n):
        """Cyclic left shift n bit of a 32bit word"""
        # & 0xffffffff means (mod 2^32)
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    @classmethod
    def _step(cls, a, b, c, d, e, wt, kt, func):
        """process a step."""
        # & 0xffffffff means (mod 2^32)
        e = (func(b, c, d) + cls._cyclic_left_shift32(a, 5) + wt + kt + e) & 0xffffffff
        return e, a, cls._cyclic_left_shift32(b, 30), c, d

    @classmethod
    def sha1_core(cls, blocks):
        """
        Core function of SHA1 algorithm.
        Notice the to reverse endianness!
        """
        func_list = (cls.F1, cls.F2, cls.F3, cls.F4)
        a, b, c, d, e = cls.INIT
        # Block
        for block in blocks:
            aa, bb, cc, dd, ee = a, b, c, d, e
            words = [ba2int(block[i * 32:(i + 1) * 32]) for i in range(16)]
            # Global step
            for t in range(80):
                if t >= 16:
                    words.append(cls._cyclic_left_shift32(
                        words[t - 3] ^ words[t - 8] ^ words[t - 14] ^ words[t - 16], 1
                    ))
                aa, bb, cc, dd, ee = cls._step(
                    aa, bb, cc, dd, ee,
                    words[t],
                    cls.K[t],
                    func_list[t // 20]
                )
            a = (a + aa) & 0xffffffff
            b = (b + bb) & 0xffffffff
            c = (c + cc) & 0xffffffff
            d = (d + dd) & 0xffffffff
            e = (e + ee) & 0xffffffff
        return int2ba(a, 32) + int2ba(b, 32) + int2ba(c, 32) + int2ba(d, 32) + int2ba(e, 32)


test_suite = {
    "": "", "a": "", "abc": "", "message digest": "",
    "abcdefghijklmnopqrstuvwxyz": "",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890": ""
}

for k, v in test_suite.items():
    my_res = SHA1.hash(k)
    hashlib_res = hashlib.sha1(k.encode()).hexdigest()
    print(f"For message: \"{k}\"")
    print(f"My: {my_res}\nHashlib: {hashlib_res}")
    print(f"\033[1;33;40m {my_res == hashlib_res} \033[0m")
# print(hashlib.sha1("abc".encode()).hexdigest())
# print(SHA1.hash("abc"))
