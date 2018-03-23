def from_bytes(b):
    return int.from_bytes(b, byteorder="little")


def to_bytes(n):
    return int.to_bytes(n & 0xFFFFFFFF, 4, byteorder="little")
