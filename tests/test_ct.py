import json

import httpx

from ssrd import ct


def test_tile_path():
    assert ct.tile_path(0) == "000"
    assert ct.tile_path(255) == "255"
    assert ct.tile_path(1000) == "x001/000"
    assert ct.tile_path(1234067) == "x001/x234/067"


def _tile(names_per_entry):
    return "\n".join(
        json.dumps({"Timestamp": 1_760_000_000_000 + i, "Subject": {"CommonName": n[0]}, "DNS": n})
        for i, n in enumerate(names_per_entry)
    ).encode()


def test_tailer_reads_full_tiles_only(conn):
    entries = [[f"shop{i}.example.org"] for i in range(256)]
    entries[10] = ["*.quantum-invest-capital.com", "quantum-invest-capital.com"]
    entries[11] = ["www.quantum-invest-capital.com"]  # duplicate registrable domain
    requested = []

    def handler(req):
        requested.append(req.url.path)
        if req.url.path.endswith("/checkpoint"):
            return httpx.Response(200, text="log.example/1\n600\nroot=\n")  # tiles 0,1 full; tile 2 partial
        if req.url.path.endswith("/tile/names/001"):
            return httpx.Response(200, content=_tile(entries))
        return httpx.Response(404)

    t = ct.Tailer(conn, client=httpx.Client(transport=httpx.MockTransport(handler)))
    conn.execute("INSERT INTO ct_state VALUES('https://log.example', 256, 0)")
    n = t.poll_log("https://log.example")
    assert n == 256
    assert not any(p.endswith("/002") for p in requested)  # partial tile skipped
    rows = conn.execute("SELECT domain, ct_ts FROM candidates").fetchall()
    assert [r[0] for r in rows] == ["quantum-invest-capital.com"]
    assert conn.execute("SELECT next_index FROM ct_state").fetchone()[0] == 512
    v = conn.execute("SELECT attempt, due_at FROM visits").fetchone()
    assert v[0] == 1 and v[1] == rows[0][1] + 1200


def test_tailer_starts_at_head(conn):
    def handler(req):
        return httpx.Response(200, text="log.example/1\n1000\nroot=\n")

    t = ct.Tailer(conn, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert t.poll_log("https://log.example") == 0
    assert conn.execute("SELECT next_index FROM ct_state").fetchone()[0] == 768
