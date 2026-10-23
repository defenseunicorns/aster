#!/usr/bin/env python3
"""Independent stdlib wire construction; no Rust encoder or bindings.

Code-path/language diversity only, not an independent-team interoperability claim.
The checked-in corpus is consumed by the production Rust codecs' tests.
"""
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent
STREAM_MAGIC = b'ASM\x01'
ATTEMPT_ID = b'\x11' * 32
ATTEMPT_NONCE = b'\x22' * 32
MAX_SOURCE_CHUNK = 1024 * 1024
MAX_AUTHENTICATED_SOURCE = 401_902
SEGMENT_BYTES = 1024 * 1024
SEGMENT_OVERHEAD = 130
MAX_SEGMENT_RECORD = SEGMENT_BYTES + SEGMENT_OVERHEAD
MAX_DATA_BODY = 4 + MAX_SEGMENT_RECORD
MAX_CHECKPOINT = 128 * 1024 * 1024
MAX_PACK_WIRE = 8_591_032_320
AUTHENTICATED_NATIVE_RECORD = bytes.fromhex(
    '0000009341535452425330320002'
    + '10' * 32
    + '20' * 32
    + '0000000000000007'
    + '0000000000000000'
    + '0000000000000000'
    + '0000000000000011'
    + '00000011'
    + '00000021'
    + 'c50825dfe99c1441f251ced1ee650141c18d32dd250a3168a102f11f6e067efcc7'
)
PROTECTED_HEADER_SHA256 = {
    'profile5-protected-data-header.bin': '8b9401d11aa038741805715586df5cbf438fbba74746a9b290c31e62d6854c88',
    'profile5-protected-data-header-maximum.bin': '10bc837c1182113a5970baeb20d178b98e0c35d83ab06eef08c94672e909829d',
}


def protected_header(name):
    value = (ROOT / name).read_bytes()
    assert value.startswith(b'ASTRFR01') and len(value) <= 2048
    assert hashlib.sha256(value).hexdigest() == PROTECTED_HEADER_SHA256[name]
    return value


def u16(n):
    return struct.pack('>H', n)


def request(offset=0, total=32768, length=16384, direction=2):
    return (b'ASM\x01\xa1' + bytes([direction]) + b'\x01' * 32
            + b'\x02' * 33 + struct.pack('>QQI', total, offset, length)
            + b'\x03' * 32)


def schedule(*entries):
    return b'ABRS\x01' + u16(len(entries)) + b''.join(entries)


def digest(value):
    return hashlib.sha256(b'ASTER/blob-ranges-stream/schedule/v1\0' + value).digest()


def corpus():
    rows = []

    def add(ok, kind, name, wire):
        rows.append(('ACCEPT' if ok else 'REJECT', kind, name, wire.hex()))

    first, second = request(), request(16384)
    base = schedule(first, second)
    for name, wire in [('empty', schedule()), ('two', base),
                       ('resume', schedule(second)),
                       ('maximum', schedule(*(request(i * 16384, 64 * 16384)
                                              for i in range(64))))]:
        add(True, 'schedule', name, wire)
    for name, wire in [('duplicate', schedule(first, first)), ('reversed', schedule(second, first)),
                       ('gap', schedule(request(0, 65536), request(32768, 65536))),
                       ('total-conflict', schedule(first, request(16384, 32769))),
                       ('direction', schedule(request(direction=1))),
                       ('zero-length', schedule(request(length=0))),
                       ('oversize-range', schedule(request(length=16385))),
                       ('noncanonical', schedule(request(length=1))),
                       ('count-limit', b'ABRS\x01' + u16(65) + first * 65),
                       ('count-mismatch', b'ABRS\x01' + u16(3) + first + second),
                       ('truncated', base[:-1]), ('trailing', base + b'\0'),
                       ('version', b'ABRS\x02' + base[5:]),
                       ('source', schedule(first, second[:6] + b'\x04' + second[7:])),
                       ('proof', schedule(first, second[:-1] + b'\x04'))]:
        add(False, 'schedule', name, wire)
    # Data/terminal vectors bind this single one-byte request, responder direction.
    single = schedule(request(total=1, length=1))
    binding = digest(single)
    data = (b'ABRD\x01' + binding + u16(0) + b'ASM\x01\xa2'
            + single[12:98] + b'\x01' + struct.pack('>I', 1) + b'Z')
    unavailable = data[:130] + b'\x02' + struct.pack('>I', 0)
    add(True, 'data', 'one-byte', data)
    add(True, 'data', 'unavailable', unavailable)
    for name, wire in [('truncated', data[:-1]), ('trailing', data + b'\0'),
                       ('digest', data[:5] + b'\0' * 32 + data[37:]),
                       ('index', data[:37] + u16(1) + data[39:]),
                       ('direction', data[:44] + b'\x01' + data[45:]),
                       ('source', data[:45] + b'\x04' + data[46:]),
                       ('object', data[:77] + b'\x01' + data[78:]),
                       ('status', data[:130] + b'\x03' + data[131:]),
                       ('unavailable-payload', data[:130] + b'\x02' + data[131:]),
                       ('payload-length', data[:131] + struct.pack('>I', 2) + b'Z')]:
        add(False, 'data', name, wire)
    terminal = b'ABRE\x01' + binding + u16(1)
    add(True, 'terminal', 'complete', terminal)
    for name, wire in [('truncated', terminal[:-1]), ('trailing', terminal + b'\0'),
                       ('digest', terminal[:5] + b'\0' * 32 + terminal[37:]),
                       ('count', terminal[:37] + u16(0)),
                       ('kind', b'ABRD' + terminal[4:])]:
        add(False, 'terminal', name, wire)
    return ('# aster-blob-ranges-stream-records/v1\tsemantic=7,8\tprofile=4\toracle=python-stdlib\n'
            '# This is the immutable profile-4 compatibility corpus; it is never ASTRBS02 semantic-v9 data.\n' + ''.join(
        '\t'.join(row) + '\n' for row in rows)
            )


def attempt(sequence=0):
    return ATTEMPT_ID + ATTEMPT_NONCE + struct.pack('>Q', sequence)


def stream_open(total=32):
    return (STREAM_MAGIC + b'\xd6\x01\x02' + struct.pack('>HH', 9, 5)
            + b'\x33' * 32 + struct.pack('>Q', 1) + ATTEMPT_ID
            + b'\x44' * 32 + b'\x55' * 32 + b'\x66' * 32
            + struct.pack('>Q', total) + ATTEMPT_NONCE + struct.pack('>Q', 0)
            + b'\x00' + struct.pack('>I', 32) + b'\x77' * 32)


def stream_source():
    source = b'ASTRENV3' + b'\x99' * 24
    return (STREAM_MAGIC + b'\xdd' + attempt(0) + struct.pack('>III', 0, len(source), len(source))
            + source)


def inspect_native_record(record):
    """Structurally validate one exact length-prefixed ASTRBS02 pack record."""
    if len(record) < 4:
        raise ValueError('native record prefix')
    encoded_len = struct.unpack('>I', record[:4])[0]
    if encoded_len == 0 or encoded_len > MAX_SEGMENT_RECORD or len(record) != 4 + encoded_len:
        raise ValueError('native record length')
    encoded = memoryview(record)[4:]
    if encoded_len < SEGMENT_OVERHEAD or encoded[:8].tobytes() != b'ASTRBS02':
        raise ValueError('segment magic')
    if struct.unpack('>H', encoded[8:10])[0] != 2:
        raise ValueError('segment version')
    if not any(encoded[10:42]) or not any(encoded[42:74]):
        raise ValueError('segment identity')
    epoch, index, offset, total = struct.unpack('>QQQQ', encoded[74:106])
    plaintext_len, ciphertext_len = struct.unpack('>II', encoded[106:114])
    end = offset + plaintext_len
    if (epoch == 0 or total == 0 or plaintext_len == 0
            or plaintext_len > SEGMENT_BYTES or ciphertext_len != plaintext_len + 16
            or offset != index * SEGMENT_BYTES or end > total
            or (end < total and plaintext_len != SEGMENT_BYTES)
            or len(encoded) != 114 + ciphertext_len):
        raise ValueError('segment fields')
    return {
        'encoded_len': encoded_len,
        'index': index,
        'offset': offset,
        'total': total,
        'plaintext_len': plaintext_len,
        'ciphertext_len': ciphertext_len,
    }


def native_record():
    inspected = inspect_native_record(AUTHENTICATED_NATIVE_RECORD)
    assert inspected == {
        'encoded_len': 147,
        'index': 0,
        'offset': 0,
        'total': 17,
        'plaintext_len': 17,
        'ciphertext_len': 33,
    }
    return AUTHENTICATED_NATIVE_RECORD


def maximum_native_record():
    ciphertext_len = SEGMENT_BYTES + 16
    encoded = (b'ASTRBS02' + struct.pack('>H', 2) + b'\x10' * 32 + b'\x20' * 32
               + struct.pack('>QQQQII', 7, 0, 0, SEGMENT_BYTES,
                             SEGMENT_BYTES, ciphertext_len)
               + b'\x5a' * ciphertext_len)
    record = struct.pack('>I', len(encoded)) + encoded
    assert len(encoded) == MAX_SEGMENT_RECORD
    assert len(record) == MAX_DATA_BODY
    inspect_native_record(record)
    return record


def stream_accept(extent_len):
    return (STREAM_MAGIC + b'\xd7' + attempt(0) + struct.pack(
        '>QQQII', 0, 0, extent_len, MAX_DATA_BODY, MAX_CHECKPOINT))


def stream_data(extent):
    return STREAM_MAGIC + b'\xd8' + attempt(0) + struct.pack('>QI', 0, len(extent)) + extent


def stream_checkpoint(extent_len, generation=1):
    return STREAM_MAGIC + b'\xd9' + attempt(1) + struct.pack('>QQQ', extent_len, generation, extent_len)


def stream_finish(extent_len, sequence=1):
    return (STREAM_MAGIC + b'\xda' + attempt(sequence) + struct.pack('>QI', extent_len, 32)
            + b'\x88' * 32)


def stream_result(extent_len, sequence=2):
    return (STREAM_MAGIC + b'\xdb' + attempt(sequence) + struct.pack('>QB', extent_len, 1)
            + b'\x99' * 32)


def stream_ack(sequence=2):
    return STREAM_MAGIC + b'\xdc' + attempt(sequence) + b'\x99' * 32


def decode_stream_record(wire):
    """Independent structural decoder for checked-in semantic-v9/profile-5 seeds."""
    if len(wire) < 5 or wire[:4] != STREAM_MAGIC:
        raise ValueError('stream prefix')
    tag = wire[4]
    body = memoryview(wire)[5:]
    fixed = {0xd7: 104, 0xd9: 96, 0xdb: 113, 0xdc: 104}
    if tag == 0xd6:
        if len(body) not in (259, 291) or body[0:2].tobytes() != b'\x01\x02':
            raise ValueError('open length/class/direction')
        if (struct.unpack('>HH', body[2:6]) != (9, 5)
                or struct.unpack('>Q', body[174:182])[0] > MAX_PACK_WIRE
                or not any(body[182:214])):
            raise ValueError('open context/nonce')
        custody = body[222]
        source_offset = 223 + (32 if custody == 1 else 0)
        if custody not in (0, 1) or len(body) != source_offset + 36:
            raise ValueError('open custody')
        source_len = struct.unpack('>I', body[source_offset:source_offset + 4])[0]
        if source_len == 0 or source_len > MAX_AUTHENTICATED_SOURCE:
            raise ValueError('open source length')
        return tag
    if tag == 0xdd:
        if len(body) < 84 or not any(body[32:64]):
            raise ValueError('source fixed fields')
        offset, total, length = struct.unpack('>III', body[72:84])
        if length == 0 or length > MAX_SOURCE_CHUNK or total == 0 or total > MAX_AUTHENTICATED_SOURCE:
            raise ValueError('source bounds')
        if offset + length > total or len(body) != 84 + length:
            raise ValueError('source framing')
        return tag
    if tag in fixed:
        if len(body) != fixed[tag] or not any(body[32:64]):
            raise ValueError('fixed record')
        if tag == 0xd7:
            durable, _, limit, extent, checkpoint = struct.unpack('>QQQII', body[72:104])
            if durable > limit or extent == 0 or extent > MAX_DATA_BODY or checkpoint == 0 or checkpoint > MAX_CHECKPOINT:
                raise ValueError('accept bounds')
        elif tag == 0xd9:
            durable, _, limit = struct.unpack('>QQQ', body[72:96])
            if durable > limit:
                raise ValueError('checkpoint credit')
        elif tag == 0xdb and body[80] not in range(1, 7):
            raise ValueError('result code')
        return tag
    if tag == 0xd8:
        if len(body) < 84 or not any(body[32:64]):
            raise ValueError('data fixed fields')
        offset, length = struct.unpack('>QI', body[72:84])
        if length == 0 or length > MAX_DATA_BODY or offset + length > 0xffffffffffffffff:
            raise ValueError('data bounds')
        if len(body) != 84 + length:
            raise ValueError('data framing')
        inspect_native_record(body[84:].tobytes())
        return tag
    if tag == 0xda:
        if len(body) < 84 or not any(body[32:64]):
            raise ValueError('finish fixed fields')
        length = struct.unpack('>I', body[80:84])[0]
        if length == 0 or length > 64 * 1024 or len(body) != 84 + length:
            raise ValueError('finish commitment')
        return tag
    raise ValueError('unknown stream tag')


def profile5_stream_corpus():
    extent = native_record()
    accepted = [
        ('open', stream_open()), ('source', stream_source()),
        ('accept', stream_accept(len(extent))), ('data-native-record', stream_data(extent)),
        ('checkpoint', stream_checkpoint(len(extent))), ('finish', stream_finish(len(extent))),
        ('result', stream_result(len(extent))), ('ack', stream_ack()),
        ('open-max-wire', stream_open(MAX_PACK_WIRE)),
    ]
    rows = [('ACCEPT', name, wire) for name, wire in accepted]
    rows.extend([
        ('REJECT', 'open-zero-attempt', accepted[0][1][:187] + b'\x00' * 32 + accepted[0][1][219:]),
        ('REJECT', 'open-wire-overflow', stream_open(MAX_PACK_WIRE + 1)),
        ('REJECT', 'data-legacy-abx1', stream_data(b'ABX1' + b'\x00' * 12)),
        ('REJECT', 'data-zero-record-length', stream_data(b'\x00' * 4)),
        ('REJECT', 'data-coalesced-records', stream_data(extent + extent)),
        ('REJECT', 'data-truncated', accepted[3][1][:-1]),
        ('REJECT', 'data-trailing', accepted[3][1] + b'\x00'),
        ('REJECT', 'data-offset-overflow', accepted[3][1][:77] + struct.pack('>Q', 0xffffffffffffffff) + accepted[3][1][85:]),
        ('REJECT', 'result-trailing-replay-change', accepted[6][1] + b'\x00'),
        ('REJECT', 'finish-empty-commitment', accepted[5][1][:85] + struct.pack('>I', 0)),
    ])
    for status, _, wire in rows:
        decoded = True
        try:
            decode_stream_record(wire)
        except ValueError:
            decoded = False
        assert decoded == (status == 'ACCEPT')
    return '# aster-profile5-stream-records/v1\tsemantic=9\tprofile=5\toracle=python-stdlib\n' + ''.join(
        f'{status}\t{name}\t{wire.hex()}\n' for status, name, wire in rows)


def profile5_composite_corpus():
    extent = native_record()
    data_header = protected_header('profile5-protected-data-header.bin')
    rows = [
        ('ACCEPT', 'native-pack-data', b'ASD1' + struct.pack('>I', len(data_header)) + data_header + extent),
        ('REJECT', 'wrong-magic', b'ASD2' + struct.pack('>I', 2) + b'\xa1\xa2\xb1'),
        ('REJECT', 'zero-header', b'ASD1' + struct.pack('>I', 0) + b'\xb1'),
        ('REJECT', 'oversized-header', b'ASD1' + struct.pack('>I', 2049) + b'\xa1'),
        ('REJECT', 'truncated-length', b'ASD1\0\0\0'),
        ('REJECT', 'truncated-header', b'ASD1' + struct.pack('>I', 3) + b'\xa1\xa2'),
    ]
    return '# aster-profile5-composite-data-record/v1\toracle=python-stdlib\n' + ''.join(
        '\t'.join((status, name, wire.hex())) + '\n'
        for status, name, wire in rows
    )


def profile5_transcript_corpus():
    extent = native_record()
    nonempty = [stream_open(len(extent)), stream_source(), stream_accept(len(extent)),
                stream_data(extent), stream_checkpoint(len(extent)), stream_finish(len(extent)),
                stream_result(len(extent)), stream_ack()]
    empty = [stream_open(0), stream_source(), stream_accept(0), stream_finish(0, 0),
             stream_result(0, 1), stream_ack(1)]
    validate_transcript(nonempty, [0xd6, 0xdd, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc],
                        {0xd7: 0, 0xd8: 0, 0xd9: 1, 0xda: 1, 0xdb: 2, 0xdc: 2})
    validate_transcript(empty, [0xd6, 0xdd, 0xd7, 0xda, 0xdb, 0xdc],
                        {0xd7: 0, 0xda: 0, 0xdb: 1, 0xdc: 1})
    rollback = nonempty[:5] + [stream_checkpoint(len(extent), 0)]
    binding = nonempty[:4] + [nonempty[4][:37] + bytes([0x23]) * 32 + nonempty[4][69:]]
    terminal_change = nonempty + [stream_result(len(extent))[:-1] + bytes([0x98])]
    validate_rejected_transcript('rollback', rollback, nonempty)
    validate_rejected_transcript('binding', binding, nonempty)
    validate_rejected_transcript('terminal-change', terminal_change, nonempty)
    encode = lambda frames: ','.join(frame.hex() for frame in frames)
    return ('# aster-profile5-transcripts/v1\tsemantic=9\tprofile=5\n'
            + 'ACCEPT\tnonempty\t' + encode(nonempty) + '\n'
            + 'ACCEPT\tempty\t' + encode(empty) + '\n'
            + 'REJECT\trollback\t' + encode(rollback) + '\n'
            + 'REJECT\tbinding\t' + encode(binding) + '\n'
            + 'REJECT\tterminal-change\t' + encode(terminal_change) + '\n')


def validate_transcript(frames, expected_tags, expected_sequences):
    tags = [decode_stream_record(frame) for frame in frames]
    assert tags == expected_tags
    transfer_id = frames[0][51:83]
    nonce = frames[0][187:219]
    for frame, tag in zip(frames[1:], tags[1:]):
        assert frame[5:37] == transfer_id and frame[37:69] == nonce
        if tag in expected_sequences:
            assert struct.unpack('>Q', frame[69:77])[0] == expected_sequences[tag]


def validate_rejected_transcript(name, frames, accepted):
    """Prove each REJECT vector violates its named state-machine invariant."""
    tags = [decode_stream_record(frame) for frame in frames]
    if name == 'rollback':
        assert tags[-2:] == [0xd9, 0xd9]
        previous = struct.unpack('>Q', frames[-2][85:93])[0]
        rollback = struct.unpack('>Q', frames[-1][85:93])[0]
        assert previous == 1 and rollback == 0
    elif name == 'binding':
        assert tags == [0xd6, 0xdd, 0xd7, 0xd8, 0xd9]
        assert frames[-1][5:37] == accepted[0][51:83]
        assert frames[-1][37:69] != accepted[0][187:219]
    elif name == 'terminal-change':
        assert tags == [0xd6, 0xdd, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdb]
        assert frames[-1][:-1] == accepted[-2][:-1]
        assert frames[-1][-1] != accepted[-2][-1]
    else:
        raise AssertionError(f'unknown rejected transcript: {name}')


def fuzz_transcript_seed(accepted, frames):
    assert 0 < len(frames) <= 16
    return (b'AST1' + bytes([1 if accepted else 0, len(frames)])
            + b''.join(struct.pack('>I', len(frame)) + frame for frame in frames))


def main():
    offer = ('# aster-blob-ranges-stream-vectors/v1\tsemantic=7,8\toracle=python-stdlib\n'
             'ACCEPT\toffer-blob-stream-only-v1\t'
             '0105000501000100040100040003010001000201000100010200020001\n')
    outputs = {
        'blob-ranges-stream-v1.tsv': offer,
        'blob-stream-records-v1.tsv': corpus(),
        'profile5-stream-records-v1.tsv': profile5_stream_corpus(),
        'profile5-composite-data-record-v1.tsv': profile5_composite_corpus(),
        'profile5-transcripts-v1.tsv': profile5_transcript_corpus(),
    }
    for name, text in outputs.items():
        path = ROOT / 'vectors' / name
        if '--write' in sys.argv:
            path.write_text(text)
        else:
            assert path.read_text() == text, f'{path}: differs from independent construction'
    seed = ROOT.parent / 'fuzz/corpus/selected_frame_decode/blob-stream-only-offer-v1'
    seed_bytes = b'ASM\x01\xd1' + bytes.fromhex(offer.splitlines()[1].split('\t')[2])
    if '--write' in sys.argv:
        seed.write_bytes(seed_bytes)
    else:
        assert seed.read_bytes() == seed_bytes, 'fuzz offer seed differs'
    stream_seed_root = ROOT.parent / 'fuzz/corpus/stream_transfer_decode'
    accepted = [line.split('\t') for line in outputs['profile5-stream-records-v1.tsv'].splitlines()
                if line.startswith('ACCEPT\t')]
    expected_names = set()
    for _, name, hexadecimal in accepted:
        seed_path = stream_seed_root / f'profile5-{name}.hex'
        expected_names.add(seed_path.name)
        payload = f'HEX:{hexadecimal}\n'.encode()
        if '--write' in sys.argv:
            seed_path.write_bytes(payload)
        else:
            assert seed_path.read_bytes() == payload, f'{seed_path}: differs from oracle'
    extent = native_record()
    header = protected_header('profile5-protected-data-header.bin')
    composite_seeds = {
        'profile5-composite-valid.bin': b'ASD1' + struct.pack('>I', len(header)) + header + extent,
    }
    maximum = maximum_native_record()
    maximum_header = protected_header('profile5-protected-data-header-maximum.bin')
    composite_seeds['profile5-composite-maximum.bin'] = (
        b'ASD1' + struct.pack('>I', len(maximum_header)) + maximum_header + maximum)
    nonempty = [
        stream_open(len(extent)), stream_source(), stream_accept(len(extent)),
        stream_data(extent), stream_checkpoint(len(extent)), stream_finish(len(extent)),
        stream_result(len(extent)), stream_ack(),
    ]
    empty = [
        stream_open(0), stream_source(), stream_accept(0), stream_finish(0, 0),
        stream_result(0, 1), stream_ack(1),
    ]
    rollback = nonempty[:5] + [stream_checkpoint(len(extent), 0)]
    binding = nonempty[:4] + [nonempty[4][:37] + bytes([0x23]) * 32 + nonempty[4][69:]]
    replay = nonempty[:4] + [nonempty[3]] + nonempty[4:]
    terminal_change = nonempty + [stream_result(len(extent))[:-1] + bytes([0x98])]
    composite_seeds['profile5-transcript-nonempty.bin'] = fuzz_transcript_seed(True, nonempty)
    composite_seeds['profile5-transcript-empty.bin'] = fuzz_transcript_seed(True, empty)
    composite_seeds['profile5-transcript-reject-rollback.bin'] = fuzz_transcript_seed(False, rollback)
    composite_seeds['profile5-transcript-reject-binding.bin'] = fuzz_transcript_seed(False, binding)
    composite_seeds['profile5-transcript-reject-replay.bin'] = fuzz_transcript_seed(False, replay)
    composite_seeds['profile5-transcript-reject-terminal-change.bin'] = fuzz_transcript_seed(False, terminal_change)
    for name, payload in composite_seeds.items():
        expected_names.add(name)
        path = stream_seed_root / name
        if '--write' in sys.argv:
            path.write_bytes(payload)
        else:
            assert path.read_bytes() == payload, f'{path}: differs from oracle'
    if '--write' in sys.argv:
        for existing in stream_seed_root.iterdir():
            if existing.name not in expected_names:
                existing.unlink()
    else:
        assert {path.name for path in stream_seed_root.iterdir()} == expected_names
    print('Blob stream oracle: profile-4 compatibility and profile-5 corpora/seeds match independent Python construction')


if __name__ == '__main__':
    main()
