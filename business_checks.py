"""Independent business verification for reassembly.Assembler.

Runs the preserved fixture regression (checks.py), deterministic contract
checks and a seeded randomized differential test against a naive per-byte
model. Standard library only; run as `python3 business_checks.py`.
"""

import base64
import json
import os
import random
import subprocess
import sys

from fixtures import packet, reversed_packets, small
from reassembly import Assembler, CaptureConflict

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Preserved fixture regression.
# ---------------------------------------------------------------------------

def check_01_fixture_baseline():
    proc = subprocess.run([sys.executable, os.path.join(HERE, 'checks.py')],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert 'CAPTURE_ROWS_BASELINE_OK' in proc.stdout
    proc = subprocess.run([sys.executable, os.path.join(HERE, 'checks.py'),
                           'demo'], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    rows = json.loads(proc.stdout.strip().splitlines()[-1])
    assert len(rows) == 6
    assert base64.b64decode(rows[1]['payload']) == b'world'
    assert base64.b64decode(rows[4]['payload']) == b'hello'


# ---------------------------------------------------------------------------
# Deterministic contract checks.
# ---------------------------------------------------------------------------

def check_02_small_contract():
    a = Assembler()
    collected = [a.feed(row) for row in small()]
    # FIN (capture 4) arrives before the missing prefix and waits for it.
    assert collected[:4] == [[], [], [], []]
    assert collected[5] == []  # the ACK only reclaims, it emits nothing
    assert collected[4] == [
        {'type': 'data', 'flow': 'a', 'offset': 0, 'payload': b'helloworld',
         'sources': [{'offset': 0, 'length': 5, 'capture': 5},
                     {'offset': 5, 'length': 5, 'capture': 2}]},
        {'type': 'complete', 'flow': 'a', 'length': 10}]
    assert a.finish() == []


def check_03_reversed_bulk():
    a = Assembler()
    events = []
    for row in reversed_packets(4, 3):
        events.extend(a.feed(row))
    assert events == [
        {'type': 'data', 'flow': 'r', 'offset': 0,
         'payload': b'\x00' * 3 + b'\x01' * 3 + b'\x02' * 3 + b'\x03' * 3,
         'sources': [{'offset': 0, 'length': 3, 'capture': 4},
                     {'offset': 3, 'length': 3, 'capture': 3},
                     {'offset': 6, 'length': 3, 'capture': 2},
                     {'offset': 9, 'length': 3, 'capture': 1}]},
        {'type': 'complete', 'flow': 'r', 'length': 12}]
    assert a.finish() == []
    # The fixture's worst-case disorder producer, end to end.
    n, width = 10000, 32
    a = Assembler()
    blob = bytearray()
    completes = []
    for row in reversed_packets(n, width):
        for ev in a.feed(row):
            if ev['type'] == 'data':
                assert ev['offset'] == len(blob)
                blob += ev['payload']
            else:
                assert ev['type'] == 'complete'
                completes.append(ev)
    expected = b''.join(bytes([i % 251]) * width for i in range(n))
    assert bytes(blob) == expected
    assert completes == [{'type': 'complete', 'flow': 'r', 'length': n * width}]
    assert a.finish() == []


def check_04_overlap_first_arrival():
    a = Assembler()
    assert a.feed(packet('x', 'syn', 10, b'', 1)) == []
    assert a.feed(packet('x', 'data', 11, b'ABCD', 2)) == [
        {'type': 'data', 'flow': 'x', 'offset': 0, 'payload': b'ABCD',
         'sources': [{'offset': 0, 'length': 4, 'capture': 2}]}]
    # An equal overlap may extend the capture; earlier bytes keep provenance.
    assert a.feed(packet('x', 'data', 13, b'CDEF', 3)) == [
        {'type': 'data', 'flow': 'x', 'offset': 4, 'payload': b'EF',
         'sources': [{'offset': 4, 'length': 2, 'capture': 3}]}]
    # Exact retransmissions emit nothing and never win provenance.
    assert a.feed(packet('x', 'data', 11, b'AB', 4)) == []
    assert a.feed(packet('x', 'data', 13, b'CD', 5)) == []
    assert a.feed(packet('x', 'fin', 17, b'', 6)) == [
        {'type': 'complete', 'flow': 'x', 'length': 6}]
    assert a.finish() == []


def check_05_conflict_permanent():
    a = Assembler()
    a.feed(packet('x', 'syn', 10, b'', 1))
    a.feed(packet('x', 'data', 11, b'ABCD', 2))
    try:
        a.feed(packet('x', 'data', 13, b'CX', 3))  # 'X' != retained 'D'
        raise AssertionError('expected CaptureConflict')
    except CaptureConflict:
        pass
    # The whole assembler stays failed: no more feed, no finish.
    for call in (lambda: a.feed(packet('x', 'data', 11, b'ABCD', 4)),
                 lambda: a.feed(packet('y', 'syn', 0, b'', 5)),
                 a.finish):
        try:
            call()
            raise AssertionError('expected CaptureConflict')
        except CaptureConflict:
            pass


def check_06_fin_rules():
    # A consistent duplicate FIN is harmless; completion waits for the prefix.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    assert a.feed(packet('f', 'fin', 16, b'', 2)) == []   # FIN at offset 5
    assert a.feed(packet('f', 'fin', 16, b'', 3)) == []   # consistent duplicate
    assert a.feed(packet('f', 'data', 11, b'ABCDE', 4)) == [
        {'type': 'data', 'flow': 'f', 'offset': 0, 'payload': b'ABCDE',
         'sources': [{'offset': 0, 'length': 5, 'capture': 4}]},
        {'type': 'complete', 'flow': 'f', 'length': 5}]
    assert a.finish() == []
    # A second FIN at a different logical position is an error.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'fin', 16, b'', 2))
    try:
        a.feed(packet('f', 'fin', 17, b'', 3))
        raise AssertionError('expected CaptureConflict')
    except CaptureConflict:
        pass
    # FIN before observed payload is an error.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 11, b'ABCDE', 2))
    try:
        a.feed(packet('f', 'fin', 14, b'', 3))   # offset 3 < observed end 5
        raise AssertionError('expected CaptureConflict')
    except CaptureConflict:
        pass
    # Data beyond the known FIN position is an error.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'fin', 16, b'', 2))
    try:
        a.feed(packet('f', 'data', 15, b'WXYZ', 3))  # ends at offset 8 > FIN 5
        raise AssertionError('expected CaptureConflict')
    except CaptureConflict:
        pass
    # An empty stream completes immediately on FIN.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    assert a.feed(packet('f', 'fin', 11, b'', 2)) == [
        {'type': 'complete', 'flow': 'f', 'length': 0}]


def check_07_ack_rules():
    # ACK beyond FIN+1 is an error (the flow is still active: a payload
    # hole keeps the FIN from completing it).
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 11, b'ABCDE', 2))
    a.feed(packet('f', 'fin', 21, b'', 3))                # FIN at offset 10
    try:
        a.feed(packet('f', 'ack', 23, b'', 4))   # logical 12 > FIN+1 = 11
        raise AssertionError('expected CaptureConflict')
    except CaptureConflict:
        pass
    # ACK exactly at FIN+1 is allowed.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 11, b'ABCDE', 2))
    a.feed(packet('f', 'fin', 21, b'', 3))
    assert a.feed(packet('f', 'ack', 22, b'', 4)) == []   # logical 11 == FIN+1
    # Stale ACKs never move the boundary backward; forgotten prefixes are
    # no longer compared, retained bytes still are.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 11, b'ABCDEF', 2))
    assert a.feed(packet('f', 'ack', 15, b'', 3)) == []   # logical 4
    assert a.feed(packet('f', 'ack', 13, b'', 4)) == []   # stale, ignored
    assert a.feed(packet('f', 'data', 11, b'ZZZDEF', 5)) == []
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 11, b'ABCDEF', 2))
    a.feed(packet('f', 'ack', 15, b'', 3))
    try:
        a.feed(packet('f', 'data', 11, b'ZZZDZF', 4))  # differs at offset 4
        raise AssertionError('expected CaptureConflict')
    except CaptureConflict:
        pass
    # ACKs never invent bytes: the uncaptured gap stays a hole.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 16, b'FG', 2))             # offsets 5..7
    assert a.feed(packet('f', 'ack', 18, b'', 3)) == []   # logical 7
    assert a.finish() == [{'flow': 'f', 'emitted': 0,
                           'holes': [[0, 5]], 'fin': None}]


def check_08_rst():
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 11, b'ABCDE', 2))
    a.feed(packet('f', 'data', 19, b'IJ', 3))             # buffered past a gap
    assert a.feed(packet('f', 'rst', 0, b'', 4)) == [
        {'type': 'aborted', 'flow': 'f', 'offset': 5}]
    # Later rows for the aborted flow are ignored.
    assert a.feed(packet('f', 'data', 16, b'FGH', 5)) == []
    assert a.feed(packet('f', 'fin', 18, b'', 6)) == []
    assert a.feed(packet('f', 'rst', 0, b'', 7)) == []
    assert a.finish() == []
    # RST before any payload aborts an empty prefix.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    assert a.feed(packet('f', 'rst', 0, b'', 2)) == [
        {'type': 'aborted', 'flow': 'f', 'offset': 0}]


def check_09_finish_reports():
    a = Assembler()
    assert a.finish() == []                               # no flows at all
    a = Assembler()
    a.feed(packet('b', 'syn', 10, b'', 1))
    a.feed(packet('b', 'data', 11, b'ABC', 2))            # emitted 0..3
    a.feed(packet('b', 'data', 16, b'FG', 3))             # buffered 5..7
    a.feed(packet('a', 'syn', 0, b'', 4))
    a.feed(packet('a', 'data', 3, b'CD', 5))              # buffered 2..4
    a.feed(packet('c', 'syn', 9, b'', 6))
    a.feed(packet('c', 'data', 10, b'Q', 7))
    a.feed(packet('c', 'fin', 11, b'', 8))                # completes, no report
    # Lexicographic order; buffered bytes split holes.
    assert a.finish() == [
        {'flow': 'a', 'emitted': 0, 'holes': [[0, 2]], 'fin': None},
        {'flow': 'b', 'emitted': 3, 'holes': [[3, 5]], 'fin': None}]
    # A known FIN bounds the report and is reported.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 11, b'ABC', 2))
    a.feed(packet('f', 'fin', 21, b'', 3))                # FIN at offset 10
    a.feed(packet('f', 'ack', 22, b'', 4))                # FIN+1, allowed
    assert a.finish() == [{'flow': 'f', 'emitted': 3,
                           'holes': [[3, 10]], 'fin': 10}]
    # No FIN and zero holes still needs a report; finish then seals input.
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 11, b'ABC', 2))
    assert a.finish() == [{'flow': 'f', 'emitted': 3, 'holes': [],
                           'fin': None}]
    for call in (lambda: a.feed(packet('f', 'data', 14, b'D', 3)), a.finish):
        try:
            call()
            raise AssertionError('expected CaptureConflict')
        except CaptureConflict:
            pass


def check_10_wraparound():
    # ISN at the very edge: wire 0 is the first payload octet.
    a = Assembler()
    a.feed(packet('w', 'syn', 2**32 - 1, b'', 1))
    assert a.feed(packet('w', 'data', 0, b'AB', 2)) == [
        {'type': 'data', 'flow': 'w', 'offset': 0, 'payload': b'AB',
         'sources': [{'offset': 0, 'length': 2, 'capture': 2}]}]
    # ACK coordinates step the reference across 2**32 many times; a data row
    # then unwraps to a logical position past ten full wraps.
    a = Assembler()
    a.feed(packet('w', 'syn', 0, b'', 1))
    step = 2**30
    logical = 0
    cap = 1
    for _ in range(40):
        logical += step
        cap += 1
        assert a.feed(packet('w', 'ack', (1 + logical) % 2**32, b'', cap)) == []
    cap += 1
    assert a.feed(packet('w', 'data', (1 + logical) % 2**32, b'Z', cap)) == []
    assert a.finish() == [{'flow': 'w', 'emitted': 0,
                           'holes': [[0, logical]], 'fin': None}]


def check_11_reclamation_whitebox():
    def retained(st):
        total, starts = 0, []
        node = st.index.first()
        while node is not None:
            assert len(node.data) == node.end - node.start
            total += node.end - node.start
            starts.append(node.start)
            node = node.next[0]
        return total, (starts[0] if starts else None)

    a = Assembler()
    a.feed(packet('m', 'syn', 0, b'', 1))
    a.feed(packet('m', 'data', 1, bytes(range(100)), 2))
    a.feed(packet('m', 'ack', 41, b'', 3))                # logical 40
    st = a._flows['m']
    assert retained(st) == (60, 40)
    # Buffered gap-fillers beyond the frontier survive reclamation.
    a.feed(packet('m', 'data', 151, bytes(range(100, 110)), 4))  # 150..160
    a.feed(packet('m', 'data', 101, bytes(range(100, 120)), 5))  # 100..120
    a.feed(packet('m', 'ack', 201, b'', 6))               # logical 200
    st = a._flows['m']
    assert retained(st) == (10, 150)
    # Filling the hole emits straight through the buffered bytes.
    events = a.feed(packet('m', 'data', 121, bytes(range(120, 150)), 7))
    assert events == [
        {'type': 'data', 'flow': 'm', 'offset': 120,
         'payload': bytes(range(120, 150)) + bytes(range(100, 110)),
         'sources': [{'offset': 120, 'length': 30, 'capture': 7},
                     {'offset': 150, 'length': 10, 'capture': 4}]}]


def check_12_state_dropped():
    a = Assembler()
    a.feed(packet('f', 'syn', 10, b'', 1))
    a.feed(packet('f', 'data', 11, b'AB', 2))
    a.feed(packet('f', 'fin', 13, b'', 3))
    assert a._flows['f'].status == 'complete'
    assert a._flows['f'].index is None
    a.feed(packet('g', 'syn', 10, b'', 4))
    a.feed(packet('g', 'rst', 0, b'', 5))
    assert a._flows['g'].status == 'aborted'
    assert a._flows['g'].index is None


def check_13_syn_rules():
    a = Assembler()
    a.feed(packet('f', 'syn', 42, b'', 1))
    assert a.feed(packet('f', 'syn', 42, b'', 2)) == []   # same ISN retransmitted
    try:
        a.feed(packet('f', 'syn', 43, b'', 3))
        raise AssertionError('expected CaptureConflict')
    except CaptureConflict:
        pass


def check_14_no_leap_over_hole():
    a = Assembler()
    a.feed(packet('f', 'syn', 0, b'', 1))
    a.feed(packet('f', 'data', 4, b'DE', 2))              # offsets 3..5
    assert a.feed(packet('f', 'data', 1, b'AB', 3)) == [
        {'type': 'data', 'flow': 'f', 'offset': 0, 'payload': b'AB',
         'sources': [{'offset': 0, 'length': 2, 'capture': 3}]}]
    # Offset 2 is still missing: captured DE must not be leapt to.
    assert a.finish() == [{'flow': 'f', 'emitted': 2, 'holes': [[2, 3]],
                           'fin': None}]


def check_15_bridging():
    a = Assembler()
    a.feed(packet('f', 'syn', 0, b'', 1))
    a.feed(packet('f', 'data', 1, b'AB', 2))              # emitted 0..2
    a.feed(packet('f', 'data', 7, b'GH', 3))              # buffered 6..8
    a.feed(packet('f', 'data', 3, b'CD', 4))              # emitted 2..4
    # One row bridges the gap and flushes everything contiguous.
    assert a.feed(packet('f', 'data', 5, b'EF', 5)) == [
        {'type': 'data', 'flow': 'f', 'offset': 4, 'payload': b'EFGH',
         'sources': [{'offset': 4, 'length': 2, 'capture': 5},
                     {'offset': 6, 'length': 2, 'capture': 3}]}]


# ---------------------------------------------------------------------------
# Randomized differential test against a naive per-byte model.
# ---------------------------------------------------------------------------

class _ModelFlow:
    __slots__ = ('isn', 'kept', 'prov', 'emitted', 'out', 'out_prov',
                 'acked', 'forgotten', 'fin', 'max_end', 'status')

    def __init__(self, isn):
        self.isn = isn
        self.kept = {}          # retained offset -> byte
        self.prov = {}          # retained offset -> first capture
        self.emitted = 0
        self.out = bytearray()  # every emitted byte
        self.out_prov = {}      # emitted offset -> first capture
        self.acked = 0
        self.forgotten = 0
        self.fin = None
        self.max_end = 0
        self.status = 'active'


def _model_apply(mf, kind, pos, payload, capture):
    """Apply one row to the naive model; return 'error' or None."""
    if mf.status != 'active':
        return None
    if kind == 'syn':
        return None if pos == mf.isn else 'error'
    if kind == 'rst':
        mf.status = 'aborted'
        return None
    if kind == 'fin':
        if mf.fin is not None:
            return None if pos == mf.fin else 'error'
        if pos < mf.max_end:
            return 'error'
        mf.fin = pos
        if mf.emitted == pos:
            mf.status = 'complete'
        return None
    if kind == 'ack':
        if mf.fin is not None and pos > mf.fin + 1:
            return 'error'
        if pos > mf.acked:
            mf.acked = pos
            boundary = pos if pos < mf.emitted else mf.emitted
            if mf.fin is not None and boundary > mf.fin:
                boundary = mf.fin
            if boundary > mf.forgotten:
                for off in [o for o in mf.kept if o < boundary]:
                    del mf.kept[off]
                    del mf.prov[off]
                mf.forgotten = boundary
        return None
    # data
    end = pos + len(payload)
    if mf.fin is not None and end > mf.fin:
        return 'error'
    if end > mf.max_end:
        mf.max_end = end
    lo = pos if pos > mf.forgotten else mf.forgotten
    for off in range(lo, end):
        byte = payload[off - pos]
        old = mf.kept.get(off)
        if old is None:
            mf.kept[off] = byte
            mf.prov[off] = capture
        elif old != byte:
            return 'error'
    while mf.emitted in mf.kept:
        mf.out.append(mf.kept[mf.emitted])
        mf.out_prov[mf.emitted] = mf.prov[mf.emitted]
        mf.emitted += 1
    if mf.fin is not None and mf.emitted == mf.fin:
        mf.status = 'complete'
    return None


_EVENT_KEYS = {'data': {'type', 'flow', 'offset', 'payload', 'sources'},
               'complete': {'type', 'flow', 'length'},
               'aborted': {'type', 'flow', 'offset'}}


def _absorb(events, model, out, prov, completed, aborted):
    for ev in events:
        assert set(ev) == _EVENT_KEYS[ev['type']], f'bad event shape: {ev}'
        f = ev['flow']
        mf = model[f]
        if ev['type'] == 'data':
            assert isinstance(ev['payload'], bytes)
            assert ev['offset'] == len(out[f])
            pos = ev['offset']
            prev_capture = None
            for src in ev['sources']:
                assert set(src) == {'offset', 'length', 'capture'}
                assert src['offset'] == pos and src['length'] > 0
                assert src['capture'] != prev_capture  # runs are coalesced
                prev_capture = src['capture']
                for i in range(src['length']):
                    prov[f][pos + i] = src['capture']
                pos += src['length']
            assert pos == ev['offset'] + len(ev['payload'])
            out[f] += ev['payload']
        elif ev['type'] == 'complete':
            assert f not in completed
            assert mf.status == 'complete' and ev['length'] == mf.fin
            completed.add(f)
        else:
            assert f not in aborted
            assert mf.status == 'aborted' and ev['offset'] == mf.emitted
            aborted[f] = ev['offset']


def _compare(flows, model, out, prov, done, completed, aborted):
    for f in flows:
        mf = model[f]
        assert len(out[f]) == mf.emitted
        while done[f] < mf.emitted:
            off = done[f]
            assert out[f][off] == mf.out[off], f'byte mismatch at {off}'
            assert prov[f][off] == mf.out_prov[off], \
                f'provenance mismatch at {off}'
            done[f] += 1
        assert (f in completed) == (mf.status == 'complete')
        assert (f in aborted) == (mf.status == 'aborted')


def _run_scenario(rng, tag):
    flows = ['f%d' % i for i in range(rng.randrange(1, 4))]
    isn = {f: rng.choice([0, 1, 7, 2**32 - 3, 2**32 - 1, 4_000_000_000])
           for f in flows}
    asm = Assembler()
    model = {f: _ModelFlow(isn[f]) for f in flows}
    gen = {f: {} for f in flows}        # flow -> offset -> byte ever produced
    cursor = {f: 0 for f in flows}      # flow -> frontier of produced bytes
    out = {f: bytearray() for f in flows}
    prov = {f: {} for f in flows}
    done = {f: 0 for f in flows}
    completed = set()
    aborted = {}
    capture = 0

    def next_capture():
        nonlocal capture
        capture += 1
        return capture

    for f in flows:
        assert asm.feed(packet(f, 'syn', isn[f], b'', next_capture())) == []

    def make_row(f):
        mf = model[f]
        if mf.status != 'active':
            kind = rng.choice(['syn', 'data', 'ack', 'fin', 'rst'])
        else:
            roll = rng.random()
            if roll < 0.50:
                kind = 'data'
            elif roll < 0.68:
                kind = 'ack'
            elif roll < 0.80:
                kind = 'fin'
            elif roll < 0.86:
                kind = 'syn'
            elif roll < 0.90:
                kind = 'rst'
            else:
                kind = 'data'
        if kind == 'syn':
            seq = isn[f] if rng.random() < 0.9 else (isn[f] + 1) % 2**32
            return 'syn', seq, b''
        if kind == 'rst':
            return 'rst', 0, b''
        if kind == 'fin':
            if mf.fin is None:
                base = mf.max_end
                if rng.random() < 0.8 or base == 0:
                    pos = base + rng.randrange(0, 6)
                else:
                    pos = base - 1  # FIN before observed payload
            else:
                pos = mf.fin if rng.random() < 0.85 else mf.fin + 1
            return 'fin', pos, b''
        if kind == 'ack':
            if mf.fin is not None and rng.random() < 0.1:
                return 'ack', mf.fin + 2 + rng.randrange(0, 2), b''  # beyond
            hi = cursor[f] + 3
            if mf.fin is not None:
                hi = min(hi, mf.fin + 1)
            return 'ack', rng.randrange(0, hi + 1), b''
        # data
        if mf.fin is not None and mf.fin > 0:
            start = rng.randrange(0, mf.fin)
            length = min(rng.randrange(1, 10), mf.fin - start)
        else:
            roll = rng.random()
            if roll < 0.45:
                start = cursor[f]
            elif roll < 0.70:
                start = cursor[f] + rng.randrange(1, 6)   # leave a hole
            else:
                start = max(0, cursor[f] - rng.randrange(0, 25))
            length = rng.randrange(1, 10)
        payload = bytearray()
        for i in range(length):
            off = start + i
            byte = gen[f].get(off)
            if byte is None:
                byte = rng.randrange(256)
                gen[f][off] = byte
            payload.append(byte)
        payload = bytes(payload)
        if rng.random() < 0.05:  # occasional differing retransmission
            i = rng.randrange(len(payload))
            payload = payload[:i] + bytes([payload[i] ^ 0xFF]) + payload[i + 1:]
        if start + length > cursor[f]:
            cursor[f] = start + length
        return 'data', start, payload

    failed = False
    for _ in range(rng.randrange(40, 160)):
        f = rng.choice(flows)
        mf = model[f]
        kind, logical, payload = make_row(f)
        cap = next_capture()
        wire = logical if kind == 'syn' else (isn[f] + 1 + logical) % 2**32
        row = packet(f, kind, wire, payload, cap)
        expected = _model_apply(mf, kind, logical, payload, cap)
        try:
            events = asm.feed(row)
            error = None
        except CaptureConflict as exc:
            events, error = None, exc
        if expected == 'error':
            assert error is not None, f'scenario {tag}: missing conflict {row}'
            failed = True
            break
        assert error is None, f'scenario {tag}: unexpected conflict {row}: {error}'
        _absorb(events, model, out, prov, completed, aborted)
        _compare(flows, model, out, prov, done, completed, aborted)
    if not failed:
        expected_reports = []
        for f in sorted(flows):
            mf = model[f]
            if mf.status != 'active':
                continue
            ack_payload = mf.acked if mf.fin is None else min(mf.acked, mf.fin)
            target = max(mf.max_end, mf.fin or 0, ack_payload)
            holes = []
            pos = mf.emitted
            for off in sorted(o for o in mf.kept if o >= mf.emitted):
                if off > pos:
                    holes.append([pos, off])
                pos = off + 1
            if pos < target:
                holes.append([pos, target])
            expected_reports.append({'flow': f, 'emitted': mf.emitted,
                                     'holes': holes, 'fin': mf.fin})
        assert asm.finish() == expected_reports, \
            f'scenario {tag}: finish mismatch'
    # Failed or sealed, the assembler rejects everything from now on.
    for call in (lambda: asm.feed(packet('zz', 'syn', 0, b'', 1)), asm.finish):
        try:
            call()
            raise AssertionError(f'scenario {tag}: expected CaptureConflict')
        except CaptureConflict:
            pass


def check_90_differential_model():
    rng = random.Random(20261114)
    for tag in range(300):
        _run_scenario(rng, tag)


# ---------------------------------------------------------------------------

def main():
    checks = [(name, fn) for name, fn in sorted(globals().items())
              if name.startswith('check_') and callable(fn)]
    for name, fn in checks:
        fn()
        print(f'ok - {name}')
    print(f'BUSINESS_CHECKS_OK ({len(checks)} checks)')


if __name__ == '__main__':
    main()
