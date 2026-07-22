"""UF-WEB auth gate: the WebSocket connect handler is the access boundary.

`on_ws_connect` requires the per-run `_AUTH_TOKEN` (via `secrets.compare_digest`) and returns False to
refuse an unauthorized socket. The command handlers (connect_serial / send_command / flash_run / …) don't
re-check auth because a client that fails the token gate is never connected in the first place — so it can
never reach a privileged handler. These pin that gate: correct token connects, missing/wrong token is
refused, and a refused client can't drive the flasher.
"""

import pytest

webapp = pytest.importorskip("web.app")
pytest.importorskip("flask_socketio")


def _client(auth=None, **kw):
    return webapp.socketio.test_client(webapp.app, auth=auth, **kw)


def test_correct_token_connects_and_is_tracked():
    c = _client(auth={"token": webapp._AUTH_TOKEN})
    try:
        assert c.is_connected()
    finally:
        c.disconnect()


def test_wrong_token_is_refused():
    c = _client(auth={"token": "not-the-real-token"})
    assert not c.is_connected()


def test_missing_token_is_refused():
    assert not _client(auth=None).is_connected()      # no auth payload at all
    assert not _client(auth={}).is_connected()         # auth payload with no token
    assert not _client(auth={"token": ""}).is_connected()  # empty token


def test_token_via_query_string_also_connects():
    # The gate falls back to the `token` query arg when the connect auth payload has none.
    c = _client(query_string=f"token={webapp._AUTH_TOKEN}")
    try:
        assert c.is_connected()
    finally:
        c.disconnect()


def test_unauthenticated_client_cannot_reach_a_privileged_handler():
    # A refused client isn't connected, so it literally can't emit a privileged event — there is no
    # transport to a handler. The connect rejection IS the enforcement.
    c = _client(auth={"token": "wrong"})
    assert not c.is_connected()
    with pytest.raises(RuntimeError, match="not connected"):
        c.emit("flash_run", {"port": "COM1", "profile": "marauder"})
