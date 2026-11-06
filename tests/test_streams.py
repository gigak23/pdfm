import pytest

from pdfm.forge import SAMPLE_TEXT
from pdfm.parser import load
from pdfm.parser.raw import iter_objects
from pdfm.scanner import scan


def ids(result):
    return {f.id for f in result.findings}


def test_streams_are_decoded(fixtures):
    doc = load(fixtures["chained.pdf"])
    assert doc.stream(6).data == SAMPLE_TEXT
    assert doc.stream(6).info.complete
    doc.close()


def test_two_filter_chain_is_not_flagged(fixtures):
    assert "UNUSUAL_FILTER_CHAIN" not in ids(scan(fixtures["chained.pdf"]))


def test_triple_chain_is_flagged(fixtures):
    result = scan(fixtures["triple_chain.pdf"])
    assert "UNUSUAL_FILTER_CHAIN" in ids(result)
    doc = load(fixtures["triple_chain.pdf"])
    assert doc.stream(6).data == SAMPLE_TEXT
    doc.close()


def test_lzw_and_run_length_streams(fixtures):
    doc = load(fixtures["lzw_rle.pdf"])
    assert doc.stream(6).data == SAMPLE_TEXT
    assert doc.stream(7).data == SAMPLE_TEXT
    doc.close()


def test_decompression_bomb_is_detected_without_expanding(fixtures):
    result = scan(fixtures["bomb.pdf"])
    assert "DECOMPRESSION_BOMB" in ids(result)
    bomb = next(s for s in result.streams if s.num == 6)
    assert bomb.truncated and bomb.decoded_size <= 50 * 1024 * 1024


@pytest.mark.parametrize("name", ["encrypted.pdf", "encrypted_aes128.pdf", "encrypted_rc4.pdf"])
def test_encrypted_streams_are_decrypted_before_decoding(fixtures, name):
    doc = load(fixtures[name])
    assert doc.mode == "pikepdf" and doc.pdf.is_encrypted
    assert any(s.data == SAMPLE_TEXT and s.info.complete for s in doc.streams)
    assert not any(s.info.error for s in doc.streams)
    doc.close()


def test_every_filtered_stream_passes_through_the_gate(fixtures):
    # Regression: an unreadable stream must never be marked complete and handed to pikepdf.
    for name in ("clean.pdf", "chained.pdf", "lzw_rle.pdf", "encrypted.pdf"):
        doc = load(fixtures[name])
        for s in doc.streams:
            assert s.info.raw_size > 0, (name, s.ref)
        doc.close()


def test_objstm_members_visible_through_iter_heads(fixtures):
    doc = load(fixtures["objstm.pdf"])
    refs = {ref for ref, _ in doc.iter_heads()}
    assert {"2 0 R", "3 0 R", "4 0 R"} <= refs  # packed inside the object stream
    doc.close()


def test_raw_mode_decodes_streams(fixtures):
    doc = load(fixtures["no_catalog.pdf"])
    assert doc.mode == "raw"
    assert b"Hello from PDFM" in doc.stream(4).data
    doc.close()


def test_fake_object_header_inside_stream_is_ignored():
    data = (b"1 0 obj\n<< /Length 20 >>\nstream\n2 0 obj << /Type /Fake >>\nendstream\nendobj\n"
            b"3 0 obj\n<< /Type /Real >>\nendobj\n")
    assert [(o.num, o.stream_span is not None) for o in iter_objects(data)] == [(1, True), (3, False)]


def test_eof_inside_stream_is_not_counted():
    from pdfm.parser.document import load_bytes
    data = b"%PDF-1.7\n1 0 obj\n<< /Length 5 >>\nstream\n%%EOF\nendstream\nendobj\n%%EOF\n"
    doc = load_bytes(data)
    assert doc.eof_count == 1
    doc.close()
