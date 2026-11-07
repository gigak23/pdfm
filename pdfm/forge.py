"""Generate harmless PDFs that exercise PDFM's detections.

The files contain structure only, never working payloads. They're built byte by
byte so each fixture is exactly what we intend (pikepdf would normalize away
the oddities we want to test).
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import zipfile
import zlib

import pikepdf

HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"

# Fixtures that antivirus engines quarantine on disk (Windows Defender flags the heap-spray
# pattern as Exploit:JS/Mult.DJ even though there is no exploit). Tests scan these from memory,
# and `pdfm forge` only writes them when asked.
AV_SENSITIVE = {"js_spray_pattern.pdf", "embedded_eicar.pdf"}


def stream(data: bytes, extra: bytes = b"") -> bytes:
    return b"<< /Length %d%s >>\nstream\n" % (len(data), extra) + data + b"\nendstream"


def catalog(extra: bytes = b"") -> bytes:
    return b"<< /Type /Catalog /Pages 2 0 R" + extra + b" >>"


def page(extra: bytes = b"") -> bytes:
    return (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
            b" /Resources << /Font << /F1 5 0 R >> >>" + extra + b" >>")


def base_objects(text: bytes = b"Hello from PDFM") -> dict[int, bytes]:
    return {
        1: catalog(),
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: page(),
        4: stream(b"BT /F1 24 Tf 72 720 Td (" + text + b") Tj ET"),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }


def _write_objects(out: bytearray, objects: dict[int, bytes]) -> dict[int, int]:
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    return offsets


def build_pdf(objects: dict[int, bytes], root: int = 1) -> bytes:
    """A complete single-revision PDF with a classic xref table."""
    out = bytearray(HEADER)
    offsets = _write_objects(out, objects)
    size = max(objects) + 1

    xref_at = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f\r\n" % size
    for num in range(1, size):
        if num in offsets:
            out += b"%010d 00000 n\r\n" % offsets[num]
        else:
            out += b"0000000000 00000 f\r\n"
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (size, root, xref_at)
    return bytes(out)


def append_update(base: bytes, objects: dict[int, bytes], root: int = 1) -> bytes:
    """Append an incremental update that adds or replaces `objects`."""
    prev_xref = int(re.findall(rb"startxref\s+(\d+)", base)[-1])
    prev_size = int(re.findall(rb"/Size\s+(\d+)", base)[-1])
    size = max(prev_size, max(objects) + 1)

    out = bytearray(base)
    offsets = _write_objects(out, objects)
    xref_at = len(out)
    out += b"xref\n"
    for num in sorted(offsets):
        out += b"%d 1\n%010d 00000 n\r\n" % (num, offsets[num])
    out += b"trailer\n<< /Size %d /Root %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (
        size, root, prev_xref, xref_at)
    return bytes(out)


def lzw_encode(data: bytes) -> bytes:
    """PDF-style LZW (MSB-first, EarlyChange=1). Mirrors pdfm.parser.filters.lzw."""
    out = bytearray()
    acc = nbits = 0
    code_len = 9

    def emit(code: int) -> None:
        nonlocal acc, nbits
        acc = (acc << code_len) | code
        nbits += code_len
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
        acc &= (1 << nbits) - 1

    def reset() -> dict[bytes, int]:
        return {bytes([i]): i for i in range(256)}

    table, next_code = reset(), 258
    emit(256)
    w = b""
    for c in data:
        wc = w + bytes([c])
        if wc in table:
            w = wc
            continue
        emit(table[w])
        table[wc] = next_code
        next_code += 1
        # The decoder's table lags one entry behind ours, so it widens codes when it holds
        # next_code - 1 entries; EarlyChange=1 makes that happen one code early.
        if next_code >= (1 << code_len) and code_len < 12:
            code_len += 1
        if next_code >= 4094:
            emit(256)
            table, next_code, code_len = reset(), 258, 9
        w = bytes([c])
    if w:
        emit(table[w])
        next_code += 1
        if next_code >= (1 << code_len) and code_len < 12:
            code_len += 1
    emit(257)
    if nbits:
        out.append((acc << (8 - nbits)) & 0xFF)
    return bytes(out)


def run_length_encode(data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 128):
        chunk = data[i:i + 128]
        out += bytes([len(chunk) - 1]) + chunk
    return bytes(out + b"\x80")


def flate_bomb(size: int = 60 * 1024 * 1024) -> bytes:
    """`size` zero bytes deflated to well under 100 KB, compressed in chunks to keep memory low."""
    c = zlib.compressobj(9)
    block = b"\0" * (1024 * 1024)
    out = bytearray()
    for _ in range(size // len(block)):
        out += c.compress(block)
    return bytes(out + c.flush())


def with_extra(extra: dict[int, bytes]) -> bytes:
    objects = base_objects()
    objects.update(extra)
    return build_pdf(objects)


SAMPLE_TEXT = b"PDFM test stream: nothing to see here. " * 4


def small_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "harmless PDFM test archive")
    return buf.getvalue()


def build_all() -> dict[str, bytes]:
    clean = build_pdf(base_objects())

    # pikepdf can pack objects into /ObjStm streams for us.
    packed = io.BytesIO()
    with pikepdf.open(io.BytesIO(clean)) as pdf:
        pdf.save(packed, object_stream_mode=pikepdf.ObjectStreamMode.generate)

    # Owner-password-only encryption: opens without a password, but every string and stream is encrypted.
    def encrypt(**kwargs) -> bytes:
        out = io.BytesIO()
        plain = with_extra({6: stream(zlib.compress(SAMPLE_TEXT), b" /Filter /FlateDecode")})
        with pikepdf.open(io.BytesIO(plain)) as pdf:
            pdf.Root.Extra = pdf.get_object(6, 0)  # referenced, so qpdf keeps it on save
            pdf.save(out, encryption=pikepdf.Encryption(owner="pdfm-owner", user="", **kwargs))
        return out.getvalue()

    # Objects but no xref, trailer, or startxref. qpdf rebuilds the xref but drops the last object.
    no_trailer = bytearray(HEADER)
    _write_objects(no_trailer, base_objects())


    return {
        "clean.pdf": clean,
        "incremental.pdf": append_update(clean, {4: stream(b"BT /F1 24 Tf 72 720 Td (Revised) Tj ET")}),
        "objstm.pdf": packed.getvalue(),
        "encrypted.pdf": encrypt(R=6),
        "encrypted_aes128.pdf": encrypt(R=4, aes=True),
        "encrypted_rc4.pdf": encrypt(R=4, aes=False, metadata=False),
        "no_trailer.pdf": bytes(no_trailer),
        "no_catalog.pdf": no_catalog_with({}),
        "truncated.pdf": clean[: len(clean) // 2],
        # M2: stream encodings
        "chained.pdf": with_extra({6: stream(
            binascii.hexlify(zlib.compress(SAMPLE_TEXT)) + b">",
            b" /Filter [/ASCIIHexDecode /FlateDecode]")}),
        "triple_chain.pdf": with_extra({6: stream(
            base64.a85encode(binascii.hexlify(zlib.compress(SAMPLE_TEXT)) + b">") + b"~>",
            b" /Filter [/ASCII85Decode /ASCIIHexDecode /FlateDecode]")}),
        "lzw_rle.pdf": with_extra({
            6: stream(lzw_encode(SAMPLE_TEXT), b" /Filter /LZWDecode"),
            7: stream(run_length_encode(SAMPLE_TEXT), b" /Filter /RunLengthDecode"),
        }),
        "bomb.pdf": with_extra({6: stream(flate_bomb(), b" /Filter /FlateDecode")}),
        # M3: triage, actions, structure
        "js_openaction.pdf": with_extra({
            1: catalog(b" /OpenAction 6 0 R"),
            6: b"<< /Type /Action /S /JavaScript /JS (app.alert('Hello from PDFM');) >>",
        }),
        "obfuscated_name.pdf": with_extra({
            1: catalog(b" /OpenAction << /S /J#61vaScript /J#53 (app.alert('obfuscated names');) >>"),
        }),
        "launch.pdf": with_extra({
            1: catalog(b" /OpenAction 6 0 R"),
            6: b"<< /Type /Action /S /Launch /Win << /F (calc.exe) >> >>",
        }),
        # Typical benign form: field-formatting JS plus an OpenAction that only sets the view.
        "form_js.pdf": with_extra({
            1: catalog(b" /OpenAction [3 0 R /Fit] /AcroForm << /Fields [6 0 R] >>"),
            3: page(b" /Annots [6 0 R]"),
            6: b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (amount) /Rect [72 600 300 630] /P 3 0 R"
               b" /AA << /K << /S /JavaScript /JS (AFNumber_Keystroke(2, 0, 0, 0, \"\", true);) >> >> >>",
        }),
        "link.pdf": with_extra({
            3: page(b" /Annots [6 0 R]"),
            6: b"<< /Type /Annot /Subtype /Link /Rect [72 700 300 720]"
               b" /A << /S /URI /URI (https://example.com/login) >> >>",
        }),
        "trailing_zip.pdf": clean + small_zip(),
        "gif_prefix.pdf": b"GIF89a\x01\x00\x01\x00\x00\x00\x00;\n" + clean,
        # M4: JavaScript. Every script only calls app.alert; the "exploit" fixtures contain the
        # API names and filler patterns detectors look for, never a working exploit or shellcode.
        "js_obfuscated.pdf": js_on_open(
            b"var p1 = 'ap' + 'p.al'; var c = String.fromCharCode(101,114,116,40,39,104,105,39,41,59);"
            b" eval(p1 + c);"),
        "js_cve_pattern.pdf": js_on_open(
            b"if (app.viewerVersion < 9.1) { Collab.getIcon('pdfm-test-icon'); }"),
        "js_spray_pattern.pdf": js_on_open(
            b"var sled = unescape('" + b"%u9090" * 24 + b"');"
            b" while (sled.length < 0x10000) sled += sled; app.alert('done');"),
        "js_doclevel_split.pdf": with_extra({
            1: catalog(b" /OpenAction 7 0 R /Names << /JavaScript << /Names [(init) 6 0 R] >> >>"),
            6: b"<< /S /JavaScript /JS (function pdfmGreet() { app.alert('split across scripts'); }) >>",
            7: b"<< /S /JavaScript /JS (pdfmGreet();) >>",
        }),
        "js_unreferenced.pdf": with_extra({6: b"<< /S /JavaScript /JS (app.alert('orphan');) >>"}),
        "xfa_script.pdf": with_extra({
            1: catalog(b" /AcroForm << /Fields [] /XFA 6 0 R >>"),
            6: stream(b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template><subform>'
                      b'<event activity="initialize"><script contentType="application/x-javascript">'
                      b'app.alert(&quot;xfa&quot;);</script></event></subform></template></xdp:xdp>'),
        }),
        "js_raw_mode.pdf": no_catalog_with({6: b"<< /S /JavaScript /J#53 (app.alert\\('raw'\\);) >>"}),
        # M5: embedded files and IOCs. Hosts use the reserved .invalid TLD and TEST-NET IPs.
        "embedded_text.pdf": embed(b"notes.txt", b"Meeting notes: nothing to see here.\n"),
        "embedded_exe.pdf": embed(b"invoice.pdf.exe", fake_pe_header()),
        "embedded_docm.pdf": embed(b"report.docm", office_zip_with_macro_part()),
        "embedded_pdf.pdf": embed(b"attachment.pdf", js_on_open(
            b"if (app.viewerVersion < 9.1) { Collab.getIcon('pdfm-test-icon'); }")),
        "embedded_eicar.pdf": embed(b"eicar.com", EICAR),
        "unc_gotor.pdf": with_extra({
            1: catalog(b" /OpenAction << /S /GoToR /F (\\\\\\\\pdfm-test.invalid\\\\share\\\\doc.pdf) /D [0 /Fit] >>"),
        }),
        "launch_cmd.pdf": with_extra({
            1: catalog(b" /OpenAction << /S /Launch /Win << /F (cmd.exe) /P (/c echo pdfm-test) >> >>"),
        }),
        "ip_uri.pdf": with_extra({
            3: page(b" /Annots [6 0 R]"),
            6: b"<< /Type /Annot /Subtype /Link /Rect [72 700 300 720]"
               b" /A << /S /URI /URI (http://192.0.2.10/landing) >> >>",
        }),
        "js_launchurl.pdf": js_on_open(b"app.launchURL('http://' + 'pdfm-test.invalid/landing', true);"),
        # M6: one fixture per bundled YARA rule (patterns only).
        "fontmatrix_string.pdf": with_extra({
            5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica"
               b" /FontMatrix [0.001 0 0 0.001 0 (0\\); app.alert\\('pdfm'\\);//)] >>",
        }),
        "xfa_tiff.pdf": with_extra({
            1: catalog(b" /AcroForm << /Fields [] /XFA 6 0 R >>"),
            6: stream(b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template><subform><field><value>'
                      b'<image contentType="image/tif">SUkqAAgAAAA=</image></value></field></subform>'
                      b"</template></xdp:xdp>"),
        }),
        "pe_in_stream.pdf": with_extra({6: stream(zlib.compress(fake_pe_with_stub()), b" /Filter /FlateDecode")}),
        "swf_stream.pdf": with_extra({6: stream(b"FWS\x0a" + b"\0" * 28)}),
        # M7: phishing lures, modelled on real MalwareBazaar samples. Hosts are all .invalid.
        "phish_brand_lure.pdf": lure_pdf(
            b"https://account-booking.pdfm-test.invalid/?account.booking.com",
            js=b"app.alert('Reader not compatible! Please open it in the browser.');"),
        "phish_link_only.pdf": lure_pdf(b"https://secure-docusign.pdfm-test.invalid/view"),
        "benign_flyer.pdf": lure_pdf(b"https://www.example.org/register"),
        # Old-style cross-document link, as found in GovDocs1 government reports.
        "launch_document.pdf": with_extra({
            3: page(b" /Annots [6 0 R]"),
            6: b"<< /Type /Annot /Subtype /Link /Rect [72 700 300 720]"
               b" /A << /S /Launch /F (../ARTICLES/080902.pdf) >> >>",
        }),
        "download_lure.pdf": with_extra({
            3: page(b" /Annots [6 0 R]"),
            6: b"<< /Type /Annot /Subtype /Link /Rect [72 700 300 720]"
               b" /A << /S /URI /URI (https://shipping.pdfm-test.invalid/IN/PO/invoice.scr.xz) >> >>",
        }),
        "schemeless_link.pdf": with_extra({
            3: page(b" /Annots [6 0 R]"),
            6: b"<< /Type /Annot /Subtype /Link /Rect [72 700 300 720]"
               b" /A << /S /URI /URI (www.pdfm-test.invalid/login) >> >>",
        }),
        **({"qr_lure.pdf": lure_pdf(None, image=qr_image(b"https://login-microsoft.pdfm-test.invalid/mfa"))}
           if qr_image(b"x") is not None else {}),
    }


def lure_pdf(url: bytes | None, js: bytes | None = None, image: tuple[bytes, int, int] | None = None) -> bytes:
    """One page that is mostly an image, with a big clickable "button" (and/or a QR code)."""
    pixels, width, height = image or (b"\xc0" * 600 * 400, 600, 400)
    objects = base_objects()
    objects[1] = catalog(b" /OpenAction 8 0 R" if js else b"")
    objects[3] = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
                  b" /Resources << /Font << /F1 5 0 R >> /XObject << /Im1 6 0 R >> >>"
                  + (b" /Annots [7 0 R]" if url else b"") + b" >>")
    objects[4] = stream(b"q 500 0 0 400 56 300 cm /Im1 Do Q BT /F1 12 Tf 72 280 Td (Your document is ready) Tj ET")
    objects[6] = stream(zlib.compress(pixels), b" /Type /XObject /Subtype /Image /Width %d /Height %d"
                        b" /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode" % (width, height))
    if url:
        objects[7] = (b"<< /Type /Annot /Subtype /Link /Rect [56 300 556 700] /Border [0 0 0]"
                      b" /A << /S /URI /URI (" + url + b") >> >>")
    if js:
        objects[8] = b"<< /S /JavaScript /JS (" + js + b") >>"
    return build_pdf(objects)


def qr_image(text: bytes) -> tuple[bytes, int, int] | None:
    """Grayscale QR code (raw 8-bit pixels, width, height), or None without the optional OpenCV."""
    try:
        import cv2
    except ImportError:
        return None
    code = cv2.QRCodeEncoder.create().encode(text.decode())
    code = cv2.resize(code, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    code = cv2.copyMakeBorder(code, 32, 32, 32, 32, cv2.BORDER_CONSTANT, value=255)
    return code.tobytes(), code.shape[1], code.shape[0]


# Assembled at runtime so antivirus doesn't quarantine this source file.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def embed(name: bytes, data: bytes) -> bytes:
    """A PDF carrying one attached file through the /EmbeddedFiles name tree."""
    return with_extra({
        1: catalog(b" /Names << /EmbeddedFiles << /Names [(" + name + b") 6 0 R] >> >>"),
        6: b"<< /Type /Filespec /F (" + name + b") /UF (" + name + b") /EF << /F 7 0 R >> >>",
        7: stream(zlib.compress(data), b" /Type /EmbeddedFile /Filter /FlateDecode"),
    })


def fake_pe_header() -> bytes:
    """Just enough of a PE header to be recognized; no sections, no code, cannot run."""
    return b"MZ" + b"\0" * 58 + (0x40).to_bytes(4, "little") + b"PE\0\0" + b"\0" * 64


def fake_pe_with_stub() -> bytes:
    """A PE header with the usual DOS stub message; still no sections and no code."""
    header = bytearray(0x80)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    header[0x4E:0x4E + len(stub)] = stub
    return bytes(header) + b"PE\0\0" + b"\0" * 64


def office_zip_with_macro_part() -> bytes:
    """A DOCX-shaped ZIP that declares a VBA project. The project part is empty: no macro code."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<document/>")
        z.writestr("word/vbaProject.bin", b"")
    return buf.getvalue()


def js_on_open(code: bytes) -> bytes:
    return with_extra({
        1: catalog(b" /OpenAction 6 0 R"),
        6: b"<< /Type /Action /S /JavaScript /JS 7 0 R >>",
        7: stream(code),
    })


def no_catalog_with(extra: dict[int, bytes]) -> bytes:
    """Objects with no xref and no catalog: forces PDFM's raw-mode fallback."""
    objects = base_objects()
    del objects[1]
    objects.update(extra)
    out = bytearray(HEADER)
    _write_objects(out, objects)
    return bytes(out)
