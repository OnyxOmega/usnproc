"""
usnproc_evtx.py -- native, standalone EVTX writer for usnproc.

Writes a Windows Event Log (.evtx, format 3.1) file directly, with no Windows
Event Log service, no ReportEvent and no channel registration on the analysis
VM (DESIGN_LOCK Q10/Q11). That gives usnproc full control of each record:

  * TimeCreated / record timestamp = the USN record's own Timestamp (Q11)
  * Computer                       = the SOURCE machine's hostname (Q10)
  * Provider Name                  = USNJournalMonitor (usnmon compatible)

Each record renders to the same shape as a classic ReportEvent event written
by usnmon:

  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="USNJournalMonitor"/>
      <EventID Qualifiers="0">100</EventID>
      <Level>4</Level> <Task>0</Task> <Keywords>0x80000000000000</Keywords>
      <TimeCreated SystemTime="..."/> <EventRecordID>n</EventRecordID>
      <Channel>FileSystem</Channel> <Computer>HOST</Computer> <Security/>
    </System>
    <EventData> <Data>blob</Data> <Data>..</Data> x N </EventData>
  </Event>

so usnmon's EvtxECmd maps (/Event/EventData/Data[N]) apply unchanged.

Layout notes (format per libevtx documentation, cross-checked by reading the
output back with python-evtx in the test suite):
  file header 4096 bytes, then 64 KiB chunks. Each chunk: 512-byte header
  (incl. string and template pointer tables), then event records. One BinXML
  template per distinct Data count is defined resident in each chunk on first
  use and referenced by offset afterwards. All values are substitutions.
"""

import struct
import uuid
import zlib

FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512
RECORD_MAGIC = 0x00002A2A
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# BinXML value types
T_NULL, T_WSTR, T_UINT8, T_UINT16, T_UINT64, T_FILETIME, T_HEX64 = (
    0x00, 0x01, 0x04, 0x06, 0x0A, 0x11, 0x15)

# Fixed substitution slots (index -> meaning); EventData strings follow.
S_PROVIDER, S_QUAL, S_EID, S_LEVEL, S_TASK, S_KEYWORDS, S_TIME, S_RECID, \
    S_CHANNEL, S_COMPUTER = range(10)
N_FIXED = 10
CLASSIC_KEYWORDS = 0x0080000000000000   # what ReportEvent events carry
LEVEL_WARNING, LEVEL_INFO = 3, 4


def _crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def _name_hash(name):
    h = 0
    for ch in name:
        h = (h * 65599 + ord(ch)) & 0xFFFFFFFF
    return h & 0xFFFF


class _TemplateBuilder:
    """Builds one BinXML template body at a known chunk offset, so element
    names can be written inline (name offset == its own position)."""

    def __init__(self, base_offset):
        self.base = base_offset     # chunk offset where self.buf[0] will live
        self.buf = bytearray()

    def _pos(self):
        return self.base + len(self.buf)

    def _name(self, name):
        # inline NameString: next(4) hash(2) count(2) utf16 + NUL(2)
        self.buf += struct.pack("<IHH", 0, _name_hash(name), len(name))
        self.buf += name.encode("utf-16-le") + b"\x00\x00"

    def element(self, name, attrs=(), content=None):
        """attrs: list of (name, sub_id, type). content: None (empty element),
        ('sub', id, type) or a list of callables building child elements."""
        start = len(self.buf)
        self.buf += struct.pack("<BHII", 0x41 if attrs else 0x01, 0xFFFF, 0, 0)
        name_off_pos = len(self.buf) - 4
        struct.pack_into("<I", self.buf, name_off_pos, self._pos())
        self._name(name)
        if attrs:
            attr_size_pos = len(self.buf)
            self.buf += b"\x00\x00\x00\x00"
            a_start = len(self.buf)
            for i, (aname, sid, typ) in enumerate(attrs):
                more = i < len(attrs) - 1
                self.buf += struct.pack("<BI", 0x46 if more else 0x06, 0)
                struct.pack_into("<I", self.buf, len(self.buf) - 4, self._pos())
                self._name(aname)
                self.buf += struct.pack("<BHB", 0x0D, sid, typ)
            struct.pack_into("<I", self.buf, attr_size_pos, len(self.buf) - a_start)
        if content is None:
            self.buf += b"\x03"                     # close empty element
        else:
            self.buf += b"\x02"                     # close start element
            if isinstance(content, tuple):
                _, sid, typ = content
                self.buf += struct.pack("<BHB", 0x0D, sid, typ)
            else:
                for build in content:
                    build()
            self.buf += b"\x04"                     # end element
        # data size = bytes after the size field through the end token
        struct.pack_into("<I", self.buf, start + 3, len(self.buf) - (start + 7))


def build_template(base_offset, n_data):
    """Return BinXML for the event template (fragment header .. EOF), to be
    placed at chunk offset base_offset."""
    t = _TemplateBuilder(base_offset)
    t.buf += b"\x0f\x01\x01\x00"                    # fragment header
    E = t.element
    first_data = N_FIXED

    def system():
        E("System", content=[
            lambda: E("Provider", attrs=[("Name", S_PROVIDER, T_WSTR)]),
            lambda: E("EventID", attrs=[("Qualifiers", S_QUAL, T_UINT16)],
                      content=("sub", S_EID, T_UINT16)),
            lambda: E("Level", content=("sub", S_LEVEL, T_UINT8)),
            lambda: E("Task", content=("sub", S_TASK, T_UINT16)),
            lambda: E("Keywords", content=("sub", S_KEYWORDS, T_HEX64)),
            lambda: E("TimeCreated", attrs=[("SystemTime", S_TIME, T_FILETIME)]),
            lambda: E("EventRecordID", content=("sub", S_RECID, T_UINT64)),
            lambda: E("Channel", content=("sub", S_CHANNEL, T_WSTR)),
            lambda: E("Computer", content=("sub", S_COMPUTER, T_WSTR)),
            lambda: E("Security"),
        ])

    def event_data():
        E("EventData", content=[
            (lambda i=i: E("Data", content=("sub", first_data + i, T_WSTR)))
            for i in range(n_data)])

    # xmlns is written as a plain attribute value on <Event>
    start = len(t.buf)
    t.buf += struct.pack("<BHII", 0x41, 0xFFFF, 0, 0)
    struct.pack_into("<I", t.buf, len(t.buf) - 4, t._pos())
    t._name("Event")
    attr_size_pos = len(t.buf)
    t.buf += b"\x00\x00\x00\x00"
    a_start = len(t.buf)
    t.buf += struct.pack("<BI", 0x06, 0)
    struct.pack_into("<I", t.buf, len(t.buf) - 4, t._pos())
    t._name("xmlns")
    t.buf += struct.pack("<BBH", 0x05, T_WSTR, len(EVENT_NS)) + EVENT_NS.encode("utf-16-le")
    struct.pack_into("<I", t.buf, attr_size_pos, len(t.buf) - a_start)
    t.buf += b"\x02"
    system()
    event_data()
    t.buf += b"\x04"
    struct.pack_into("<I", t.buf, start + 3, len(t.buf) - (start + 7))
    t.buf += b"\x00"                                # EOF
    return bytes(t.buf)


def _encode_value(typ, value):
    if typ == T_WSTR:
        return (value or "").encode("utf-16-le")
    if typ == T_UINT8:
        return struct.pack("<B", value)
    if typ == T_UINT16:
        return struct.pack("<H", value)
    if typ in (T_UINT64, T_HEX64, T_FILETIME):
        return struct.pack("<Q", value)
    raise ValueError(typ)


class _Chunk:
    def __init__(self, number):
        self.number = number
        self.buf = bytearray(CHUNK_SIZE)
        self.used = CHUNK_HEADER_SIZE
        self.first_id = None
        self.last_id = None
        self.last_rec_off = 0
        self.templates = {}            # n_data -> template def chunk offset

    def try_add(self, record_id, filetime, values, n_data):
        """values: list of (type, value) for all substitutions. Returns False
        if the record doesn't fit in this chunk."""
        rec_off = self.used
        body = bytearray(b"\x0f\x01\x01\x00")      # fragment header
        inst_off = rec_off + 24 + len(body)        # 24 = record header
        tmpl_off = self.templates.get(n_data)
        resident = tmpl_off is None
        if resident:
            tmpl_off = inst_off + 10
        guid = uuid.uuid5(uuid.NAMESPACE_URL, "usnproc/template/%d" % n_data).bytes_le
        tmpl_id = struct.unpack_from("<I", guid, 0)[0]
        body += struct.pack("<BBII", 0x0C, 0x01, tmpl_id, tmpl_off)
        if resident:
            data = build_template(tmpl_off + 24, n_data)
            body += struct.pack("<I", 0) + guid + struct.pack("<I", len(data)) + data
        encoded = [(typ, _encode_value(typ, v)) for typ, v in values]
        body += struct.pack("<I", len(encoded))
        for typ, raw in encoded:
            body += struct.pack("<HBB", len(raw), typ, 0)
        for _, raw in encoded:
            body += raw
        size = 24 + len(body) + 4
        if rec_off + size > CHUNK_SIZE:
            return False
        rec = struct.pack("<IIQQ", RECORD_MAGIC, size, record_id, filetime) + body \
            + struct.pack("<I", size)
        self.buf[rec_off:rec_off + size] = rec
        if resident:
            self.templates[n_data] = tmpl_off
            # template pointer table (32 buckets at 0x180)
            bucket = tmpl_id % 32
            if struct.unpack_from("<I", self.buf, 0x180 + bucket * 4)[0] == 0:
                struct.pack_into("<I", self.buf, 0x180 + bucket * 4, tmpl_off)
        self.used += size
        self.last_rec_off = rec_off
        if self.first_id is None:
            self.first_id = record_id
        self.last_id = record_id
        return True

    def finalize(self):
        b = self.buf
        b[0:8] = b"ElfChnk\x00"
        struct.pack_into("<QQQQIII", b, 8, self.first_id, self.last_id,
                         self.first_id, self.last_id, 128, self.last_rec_off, self.used)
        struct.pack_into("<I", b, 52, _crc32(bytes(b[CHUNK_HEADER_SIZE:self.used])))
        struct.pack_into("<I", b, 120, 0)
        struct.pack_into("<I", b, 124, _crc32(bytes(b[0:120]) + bytes(b[128:512])))
        return bytes(b)


def file_header(n_chunks, next_record_id):
    h = bytearray(FILE_HEADER_SIZE)
    h[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQIHHHH", h, 8, 0, max(n_chunks - 1, 0), next_record_id,
                     128, 1, 3, FILE_HEADER_SIZE, n_chunks)
    struct.pack_into("<I", h, 120, 0)          # flags: clean, not full
    struct.pack_into("<I", h, 124, _crc32(bytes(h[0:120])))
    return bytes(h)


class EvtxWriter:
    """Stream events into a new .evtx file. Never overwrites (mode 'xb')."""

    def __init__(self, path, computer, provider="USNJournalMonitor",
                 channel="FileSystem"):
        self.path = path
        self.computer = computer or ""
        self.provider = provider
        self.channel = channel
        self._f = open(path, "xb")
        self._f.write(b"\x00" * FILE_HEADER_SIZE)   # placeholder header
        self._chunk = None
        self._n_chunks = 0
        self.next_record_id = 1
        self.count = 0

    def write(self, event_id, filetime, strings, level=LEVEL_INFO):
        """event_id: int; filetime: record time (FILETIME ticks);
        strings: EventData <Data> values in order; level: 4 info, 3 warning."""
        values = [
            (T_WSTR, self.provider), (T_UINT16, 0), (T_UINT16, event_id),
            (T_UINT8, level), (T_UINT16, 0), (T_HEX64, CLASSIC_KEYWORDS),
            (T_FILETIME, filetime), (T_UINT64, self.next_record_id),
            (T_WSTR, self.channel), (T_WSTR, self.computer),
        ] + [(T_WSTR, str(s)) for s in strings]
        if self._chunk is None:
            self._chunk = _Chunk(self._n_chunks)
        if not self._chunk.try_add(self.next_record_id, filetime, values, len(strings)):
            self._flush_chunk()
            self._chunk = _Chunk(self._n_chunks)
            if not self._chunk.try_add(self.next_record_id, filetime, values, len(strings)):
                raise ValueError("event too large for one EVTX chunk")
        self.next_record_id += 1
        self.count += 1

    def _flush_chunk(self):
        if self._chunk is not None and self._chunk.first_id is not None:
            self._f.write(self._chunk.finalize())
            self._n_chunks += 1
        self._chunk = None

    def close(self):
        if self._f is None:
            return
        self._flush_chunk()
        self._f.seek(0)
        self._f.write(file_header(self._n_chunks, self.next_record_id))
        self._f.close()
        self._f = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def write_empty(path):
    """Header-only .evtx (journal state 3 -- empty). Never overwrites."""
    with open(path, "xb") as f:
        f.write(file_header(0, 1))
