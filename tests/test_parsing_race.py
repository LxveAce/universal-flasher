"""Regression: the MarauderParser indexed accessors must not race the serial reader thread.

indexed_aps/indexed_stations used key-then-index (`[self.aps[i] for i in sorted(self.aps)]`),
which raises KeyError when the reader thread clears/repopulates the dict mid-iteration — in the web
front-end feed() runs on the reader thread while the _table_pusher thread reads the accessors, so a
transient KeyError silently killed the live-table pusher (which had no try/except). The values()-
snapshot form must never raise under the same race; the pusher is separately guarded in web/app.py.
"""

import sys
import threading

from uf_core.parsing import AP, MarauderParser, Station


def test_indexed_aps_ordered_by_index():
    p = MarauderParser()
    p.feed(">> list -a")
    p.feed("[0][CH:1] First -50")       # idx 0 resets the (empty) table first
    p.feed("[2][CH:1] Third -70")       # then insert out of index order
    p.feed("[1][CH:1] Second -60")
    assert list(p.aps) == [0, 2, 1]                    # dict insertion order is NOT sorted
    assert [a.ssid for a in p.indexed_aps()] == ["First", "Second", "Third"]


def test_indexed_accessors_survive_concurrent_reader_mutation():
    p = MarauderParser()
    errors: list = []
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            if i % 8 == 0:                 # mimic the idx==0 table reset on every fresh dump
                p.aps.clear()
                p.stations.clear()
            k = i % 8
            p.aps[k] = AP(index=k, ssid="x", channel="1", rssi="-50")
            p.stations[k] = Station(index=k, mac="aa:bb:cc:dd:ee:ff", rssi="-50")
            i += 1

    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)            # force frequent thread switches to expose the race
    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        for _ in range(20000):
            try:
                p.indexed_aps()
                p.indexed_stations()
                p.ap_rows()
                p.station_rows()
            except Exception as exc:       # the bug surfaced as KeyError here
                errors.append(exc)
                break
    finally:
        stop.set()
        t.join(timeout=2)
        sys.setswitchinterval(old_interval)

    assert not errors, f"indexed accessor raced the reader thread: {errors[:3]!r}"
