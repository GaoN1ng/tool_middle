"""Artificial PE32+ named import table for structural parser tests, not runnable firmware."""
import struct

def named_import_pe(names=("RSA_public_encrypt", "ECDSA_verify", "ECDH_compute_key"), dll="libcrypto-test.dll"):
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    op = 0x98
    struct.pack_into("<H", data, op, 0x20b)
    struct.pack_into("<Q", data, op+24, 0x140000000)
    struct.pack_into("<II", data, op+32, 0x1000, 0x200)
    struct.pack_into("<II", data, op+56, 0x2000, 0x200)
    struct.pack_into("<H", data, op+68, 3)
    struct.pack_into("<I", data, op+108, 16)
    struct.pack_into("<II", data, op+112+8, 0x1000, 40)
    section = op+240
    data[section:section+8] = b".idata\0\0"
    struct.pack_into("<IIII", data, section+8, 0x600, 0x1000, 0x600, 0x200)
    struct.pack_into("<I", data, section+36, 0xc0000040)
    struct.pack_into("<IIIII", data, 0x200, 0x1080, 0, 0, 0x1040, 0x10c0)
    encoded = dll.encode()+b"\0"
    data[0x240:0x240+len(encoded)] = encoded
    cursor = 0x320
    for index, name in enumerate(names):
        struct.pack_into("<Q", data, 0x280+index*8, 0x1000+cursor-0x200)
        struct.pack_into("<Q", data, 0x2c0+index*8, 0x1000+cursor-0x200)
        encoded = b"\0\0"+name.encode()+b"\0"
        data[cursor:cursor+len(encoded)] = encoded
        cursor += (len(encoded)+1)//2*2
    return bytes(data)
