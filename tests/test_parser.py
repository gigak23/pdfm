from pdfm.parser import load
from pdfm.parser.raw import scan_objects


def finding_ids(doc):
    return {f.id for f in doc.findings}


def test_clean_pdf_parses_with_pikepdf(fixtures):
    doc = load(fixtures["clean.pdf"])
    assert doc.mode == "pikepdf"
    assert doc.version == "1.7"
    assert doc.revisions == 1
    assert [o.type for o in doc.objects] == ["Catalog", "Pages", "Page", "stream", "Font"]
    assert all(o.offset is not None for o in doc.objects)
    assert finding_ids(doc) == set()
    doc.close()


def test_incremental_update_is_counted(fixtures):
    doc = load(fixtures["incremental.pdf"])
    assert doc.revisions == 2
    assert "INCREMENTAL_UPDATES" in finding_ids(doc)
    # Object 4 was redefined; the reported offset is the newer definition in the appended update.
    content = next(o for o in doc.objects if o.num == 4)
    assert content.offset >= len(fixtures["clean.pdf"].read_bytes())
    doc.close()


def test_object_stream_members_are_detected(fixtures):
    doc = load(fixtures["objstm.pdf"])
    packed = {o.type for o in doc.objects if o.in_objstm}
    assert {"Catalog", "Pages", "Page"} <= packed
    assert all(o.offset is None for o in doc.objects if o.in_objstm)
    assert "OBJECT_STREAMS" in finding_ids(doc)
    doc.close()


def test_object_hidden_from_repaired_xref_is_flagged(fixtures):
    doc = load(fixtures["no_trailer.pdf"])
    assert doc.mode == "pikepdf"
    assert {"PARSER_REPAIRED", "UNINDEXED_OBJECTS"} <= finding_ids(doc)
    doc.close()


def test_unparseable_file_falls_back_to_raw_scan(fixtures):
    doc = load(fixtures["no_catalog.pdf"])
    assert doc.mode == "raw"
    assert doc.pdf is None
    assert "PARSE_FALLBACK" in finding_ids(doc)
    assert [(o.num, o.type) for o in doc.objects] == [(2, "Pages"), (3, "Page"), (4, "stream"), (5, "Font")]


def test_truncated_file_does_not_crash(fixtures):
    doc = load(fixtures["truncated.pdf"])
    assert doc.objects
    assert "PARSER_REPAIRED" in finding_ids(doc) or doc.mode == "raw"
    doc.close()


def test_raw_scan_ignores_longer_object_numbers():
    objects = scan_objects(b"110 0 obj\n<< /Type /Page >>\nendobj\n")
    assert [(o.num, o.type) for o in objects] == [(110, "Page")]


def test_raw_scan_keeps_latest_definition():
    data = b"1 0 obj\n<< /Type /A >>\nendobj\n1 0 obj\n<< /Type /B >>\nendobj\n"
    assert [o.type for o in scan_objects(data)] == ["B"]


def test_raw_scan_handles_missing_endobj():
    objects = scan_objects(b"1 0 obj\n<< /Length 3 >>\nstream\nabc")
    assert objects[0].is_stream
