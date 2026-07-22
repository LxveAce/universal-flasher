"""UF-WEB CORS: a public bind must not lock CORS to the (unbrowsable) bind address.

`--host 0.0.0.0` (or a specific LAN IP) exposes the UI on the network, but a real client reaches the
server by the machine's IP/hostname — never `0.0.0.0`, which is not a browsable Origin. The old code
built the allow-list from the bind address, so it CORS-rejected every real LAN client and public-bind
mode didn't work at all. `_cors_origins` now returns "*" for a public bind (the per-run auth token
required on the WebSocket connect is the real gate, not CORS) and the strict localhost list for loopback.
"""

import pytest

app_mod = pytest.importorskip("web.app")


def test_public_bind_allows_any_origin():
    assert app_mod._cors_origins("0.0.0.0", 5000) == "*"
    assert app_mod._cors_origins("192.168.1.50", 8080) == "*"
    assert app_mod._cors_origins("my-host.local", 5000) == "*"


def test_loopback_bind_keeps_strict_allowlist():
    origins = app_mod._cors_origins("127.0.0.1", 5000)
    assert origins != "*"
    assert "http://127.0.0.1:5000" in origins
    assert "http://localhost:5000" in origins


def test_loopback_allowlist_tracks_the_port():
    origins = app_mod._cors_origins("localhost", 8899)
    assert "http://127.0.0.1:8899" in origins and "http://localhost:8899" in origins
