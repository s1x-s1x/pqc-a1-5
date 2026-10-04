"""Small hashlib-compatible SM3 fallback, for toy tests and verification."""

import struct


_IV = (0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
       0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E)
_MASK = 0xFFFFFFFF


def _rol(value, count):
    count %= 32
    return ((value << count) | (value >> ((32 - count) % 32))) & _MASK


class Sm3:
    name = "sm3"
    digest_size = 32
    block_size = 64

    def __init__(self, data=b""):
        self._state = _IV
        self._buffer = b""
        self._length = 0
        self.update(data)

    def copy(self):
        duplicate = object.__new__(Sm3)
        duplicate._state = self._state
        duplicate._buffer = self._buffer
        duplicate._length = self._length
        return duplicate

    def update(self, data):
        data = bytes(data)
        self._length += len(data)
        pending = self._buffer + data
        complete = len(pending) // 64 * 64
        for position in range(0, complete, 64):
            self._compress(pending[position:position + 64])
        self._buffer = pending[complete:]

    def _compress(self, block):
        words = list(struct.unpack(">16I", block))
        for j in range(16, 68):
            value = words[j - 16] ^ words[j - 9] ^ _rol(words[j - 3], 15)
            p1 = value ^ _rol(value, 15) ^ _rol(value, 23)
            words.append(p1 ^ _rol(words[j - 13], 7) ^ words[j - 6])
        a, b, c, d, e, f, g, hh = self._state
        for j in range(64):
            tj = 0x79CC4519 if j < 16 else 0x7A879D8A
            ss1 = _rol((_rol(a, 12) + e + _rol(tj, j)) & _MASK, 7)
            ss2 = ss1 ^ _rol(a, 12)
            if j < 16:
                ff, gg = a ^ b ^ c, e ^ f ^ g
            else:
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | ((~e) & g)
            tt1 = (ff + d + ss2 + (words[j] ^ words[j + 4])) & _MASK
            tt2 = (gg + hh + ss1 + words[j]) & _MASK
            d, c, b, a = c, _rol(b, 9), a, tt1
            hh, g, f = g, _rol(f, 19), e
            e = tt2 ^ _rol(tt2, 9) ^ _rol(tt2, 17)
        self._state = tuple(old ^ new for old, new in
                            zip(self._state, (a, b, c, d, e, f, g, hh)))

    def digest(self):
        duplicate = self.copy()
        padding = b"\x80" + b"\x00" * ((55 - self._length) % 64)
        padding += struct.pack(">Q", self._length * 8)
        duplicate.update(padding)
        return struct.pack(">8I", *duplicate._state)

    def hexdigest(self):
        return self.digest().hex()
