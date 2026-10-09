"""Stream actual mounted bytes; expected SHA-256 comes from a separate source formula."""
import hashlib
import struct


def independent_digest():
    digest = hashlib.sha256()
    for number in range(1024):
        offset = number * 65536
        block = bytearray((position * 31 + position // 4096) % 251 for position in range(offset, offset + 65536))
        block[:8] = struct.pack('<Q', number)
        digest.update(block)
    return digest.hexdigest()


def scan(path, digest, size=67108864):
    actual = hashlib.sha256()
    count = 0
    with open(path, 'rb', buffering=0) as handle:
        while True:
            block = handle.read(1048576)
            if not block:
                break
            count += len(block)
            actual.update(block)
    observed = actual.hexdigest()
    assert count == size, (count, size)
    assert observed == digest, (observed, digest)
    return {'bytes':count, 'digest':observed, 'independent_digest':digest}
