import base64
import binascii
import os
import zlib

import pytest

from pdfm.forge import flate_bomb, lzw_encode, run_length_encode
from pdfm.parser import filters
from pdfm.parser.filters import DecodeError, OutputLimitExceeded, decode_chain

TEXT = b"The quick brown fox jumps over the lazy dog. " * 50


def test_flate_round_trip():
    assert filters.flate(zlib.compress(TEXT), 10**6) == TEXT


def test_flate_accepts_raw_deflate_without_header():
    c = zlib.compressobj(wbits=-15)
    assert filters.flate(c.compress(TEXT) + c.flush(), 10**6) == TEXT


def test_flate_keeps_partial_output_of_corrupt_stream():
    data = zlib.compress(os.urandom(40000))
    with pytest.raises(DecodeError) as exc:
        filters.flate(data[:20000] + b"\xff" * 500 + data[20500:], 10**6)
    assert exc.value.partial


def test_flate_bomb_stops_at_limit():
    with pytest.raises(OutputLimitExceeded) as exc:
        filters.flate(flate_bomb(8 * 1024 * 1024), 1024 * 1024)
    assert len(exc.value.partial) == 1024 * 1024


def test_ascii_hex():
    assert filters.ascii_hex(b"48 65 6C\n6c6f>trailing", 100) == b"Hello"
    assert filters.ascii_hex(b"414>", 100) == b"A@"  # odd digit count pads with 0


def test_ascii85():
    encoded = base64.a85encode(TEXT) + b"~>"
    assert filters.ascii85(b"<~" + encoded, 10**6) == TEXT
    assert filters.ascii85(b"z~>", 100) == b"\0\0\0\0"


def test_run_length():
    assert filters.run_length(run_length_encode(TEXT), 10**6) == TEXT
    assert filters.run_length(b"\xfdA\x01BC\x80", 100) == b"AAAABC"


def test_lzw_spec_example():
    # ISO 32000-1 section 7.4.4.2: "-----A---B" encodes to these bytes.
    assert filters.lzw(bytes.fromhex("800B6050220C0C8501"), 100) == b"-----A---B"


@pytest.mark.parametrize("data", [TEXT, os.urandom(20000), b"a" * 100000, b""])
def test_lzw_round_trip_including_code_width_changes(data):
    assert filters.lzw(lzw_encode(data), 10**7) == data


def test_chain_decodes_in_order():
    encoded = binascii.hexlify(zlib.compress(TEXT)) + b">"
    result = decode_chain(encoded, ["ASCIIHexDecode", "FlateDecode"])
    assert result.complete and result.data == TEXT
    assert result.applied == ["ASCIIHexDecode", "FlateDecode"]


def test_chain_accepts_abbreviations():
    assert decode_chain(zlib.compress(TEXT), ["Fl"]).data == TEXT


def test_chain_stops_at_image_codec():
    result = decode_chain(zlib.compress(b"jpeg bytes"), ["FlateDecode", "DCTDecode"])
    assert result.stopped_at == "DCTDecode"
    assert result.data == b"jpeg bytes"
    assert not result.complete


def test_entropy_bounds():
    assert filters.entropy(b"") == 0
    assert filters.entropy(b"aaaa") == 0
    assert filters.entropy(bytes(range(256)) * 4) == pytest.approx(8.0)
