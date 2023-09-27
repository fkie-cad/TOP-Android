#!/us/bin/env python3

from pwn import p8, p16, u32

from typing import Tuple, List

import math
import itertools

from secrets import token_bytes

# Bytecode primitives
TYPE_EXCEPTION = 0x55
TYPE_CHAR_ARRAY = 0x1c41
TYPE_STRINGBUILDER = 0x146a


def unsigned_range(nums_bits: int) -> Tuple[int, int]:
    """
    Returns (lower, upper)
    """
    return (0, pow(2, nums_bits) - 1)

def signed_range(nums_bits: int) -> Tuple[int, int]:
    """
    Returns (lower, upper)
    """
    return (-pow(2, nums_bits - 1), pow(2, nums_bits - 1) - 1)

def assert_range(val: int, lower: int, upper: int) -> None:
    assert(val >= lower and val <= upper)

def assert_ubyte(val: int) -> None:
    assert_range(val, *unsigned_range(8))

def assert_sbyte(val: int) -> None:
    assert_range(val, *signed_range(8))

def assert_ushort(val: int) -> None:
    assert_range(val, *unsigned_range(16))

def assert_sshort(val: int) -> None:
    assert_range(val, *signed_range(16))

def assert_shbyte(val: int) -> None:
    assert_range(val, *signed_range(4))

def assert_uhbyte(val: int) -> None:
    assert_range(val, *unsigned_range(4))

def assert_uint(val: int) -> None:
    assert_range(val, *unsigned_range(32))

def const_4(vreg: int, value: int) -> bytes:
    assert_uhbyte(vreg)
    assert_shbyte(value)
    return b'\x12' + p8((value << 4) | vreg)

def const_16(vreg: int, value: int) -> bytes:
    assert_ubyte(vreg)
    assert_sshort(value)
    return b'\x13' + p8(vreg) + p16(value)

def add_int_lit_8(dst: int, src: int, value: int) -> bytes:
    assert_ubyte(dst)
    assert_ubyte(src)
    assert_sbyte(value)
    return b'\xd8' + p8(dst) + p8(src) + p8(value)

def filled_new_array_range(size: int, type_index: int, first_vreg: int) -> bytes:
    assert_ubyte(size)
    assert_ushort(type_index)
    assert_ushort(first_vreg)
    return b'\x25' + p8(size) + p16(type_index) + p16(first_vreg)

def new_array(dst: int, size: int, type_index: int) -> bytes:
    assert_uhbyte(dst)
    assert_uhbyte(size)
    assert_ushort(type_index)
    return b'\x23' + p8((size << 4) | dst) + p16(type_index)

def aget_char(dst: int, array: int, idx: int) -> bytes:
    assert_ubyte(dst)
    assert_ubyte(array)
    assert_ubyte(idx)
    return b'\x49' + p8(dst) + p8(array) + p8(idx)

def aput_char(src: int, array: int, idx: int) -> bytes:
    assert_ubyte(src)
    assert_ubyte(array)
    assert_ubyte(idx)
    return b'\x50' + p8(src) + p8(array) + p8(idx)

def xor_int_2addr(dst: int, src: int) -> bytes:
    assert_uhbyte(dst)
    assert_uhbyte(src)
    return b'\xb7' + p8((src << 4) | dst)

def if_lt(first: int, second: int, branch: int) -> bytes:
    assert_uhbyte(first)
    assert_uhbyte(second)
    assert_sshort(branch)
    return b'\x34' + p8((second << 4) | first) + p16(branch)

def throw(vreg: int) -> bytes:
    assert_ubyte(vreg)
    return b'\x27' + p8(vreg)

def return_object(vreg: int) -> bytes:
    assert_ubyte(vreg)
    return b'\x11' + p8(vreg)

def move_exception(vreg: int) -> bytes:
    assert_ubyte(vreg)
    return b'\x0d' + p8(vreg)

def encrypt(msg: bytes, key: int) -> bytes:
    assert_ubyte(key)
    return b''.join([ p8(c ^ key) for c in msg ])

def generate_table(size: int) -> bytes:
    assert_uint(size)

    # Create message
    key = 0x42
    message = encrypt(b'flag', key)

    # Generate offsets for required primitives
    # Register Allocations:
    # - v0: Exception object
    # - v1: Virtual program counter
    # - v2: Secret key
    # - v3: Character array of decoded values
    # - v4: Temporary value for holding encoded chars
    # - v5: Array index
    v0, v1, v2, v3, v4, v5, v6 = (i for i in range(7))
    required = [

        const_16(v2, len(message)),
        new_array(v3, v2, TYPE_CHAR_ARRAY), # Initialize decoded value array
        const_16(v2, key),  # Initialize secret key
        const_4(v5, 0), # Initialize array index

    ]

    required += list(itertools.chain.from_iterable(list(itertools.chain.from_iterable([
        [
            [
                const_16(v4, message[i]),
                xor_int_2addr(v4, v2),
                aput_char(v4, v3, v5),
                add_int_lit_8(v5, v5, 1),
            ]
            for i in range(len(message))
        ]
    ]))))

    required += [

        move_exception(v2),
        return_object(v3)

    ]

    # Generate random, non-overlapping offsets of gadgets
    required = [
        gadget + throw(v0)
        for gadget in required
    ]

    num_bytes = math.ceil(math.log2(size)) // 8
    allocations: List[Tuple[int, bytes]] = []

    for gadget in required:
        offset = -1
        length = len(gadget)

        while offset == -1:
            rand_offset = int.from_bytes(token_bytes(num_bytes), 'little')
            if rand_offset % 2 != 0:
                continue
            if rand_offset + length > size:
                continue

            if not any([ (off <= rand_offset and rand_offset < off + len(gad)) or
                         (rand_offset <= off and off < rand_offset + length) for off, gad in allocations ]):
                # Found non - overlapping offset
                offset = rand_offset
        
        allocations.append(( offset, gadget ))

    # Write gadgets to random table
    table = list(token_bytes(size))
    for offset, gadget in allocations:
        for i in range(len(gadget)):
            table[offset+i] = gadget[i]

    return allocations, table


def main():
    allocations, table = generate_table(pow(2, 16))
    print('{\\')
    for offset, gadget in allocations:
        # print(f'Offset: {hex(offset)} <- {gadget}')
        print(f'\tJUMP_OFFSET({hex(offset)}),\\')
    print('}')

    print()
    print('{')
    for t in table:
        print('\'\\x{:02x}\','.format(t), end='')
    print('}')

if __name__ == '__main__':
    main()