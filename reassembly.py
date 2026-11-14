"""Ordered TCP payload reassembly from one-way capture rows.

Receiver stage for the acquisition pipeline described in CONTRACT.md. It
consumes decoded capture rows (the fixtures.py row format) and produces,
per flow, an ordered payload stream with first-capture provenance, FIN
completion, RST abortion, cumulative-ACK reclamation and exact finish()
gap reports.

Standard library only; no sockets, no TCP stack, no persistence.
"""

import random

__all__ = ['Assembler', 'CaptureConflict']

_WIRE = 1 << 32   # wire sequence numbers are uint32 and wrap here
_HALF = 1 << 31
_LEVELS = 32      # skip-list tower height, expected headroom ~2**32 fragments


class CaptureConflict(Exception):
    """Conflicting capture bytes or a protocol/state violation.

    Once raised, the whole assembler is permanently failed: every later
    feed()/finish() call raises CaptureConflict again.
    """


class _Frag:
    """One retained run of first-arrival bytes; never one object per byte."""

    __slots__ = ('start', 'end', 'data', 'capture', 'next')

    def __init__(self, start, end, data, capture, level):
        self.start = start       # absolute stream offset; ISN+1 is offset zero
        self.end = end           # half-open end
        self.data = data         # bytes of length end - start
        self.capture = capture   # capture-row number that first supplied these bytes
        self.next = [None] * (level + 1)


class _Index:
    """Skip list of disjoint _Frag runs ordered by start offset.

    Search and insert are expected O(log F); overlap walks, gap-filling
    insert runs and prefix reclamation cost O(log F + K) for K actually
    touched fragments, so no packet ever scans or shifts every fragment.
    """

    __slots__ = ('head', 'level', 'rng')

    def __init__(self, rng):
        self.head = _Frag(0, 0, b'', -1, _LEVELS)
        self.level = 0
        self.rng = rng

    def _random_level(self):
        level = 0
        roll = self.rng.random
        while level < _LEVELS and roll() < 0.5:
            level += 1
        return level

    def predecessors(self, start, u=None):
        """Vector u with u[i] = last level-i node starting before `start`."""
        if u is None:
            u = [self.head] * (_LEVELS + 1)
        node = self.head
        for i in range(self.level, -1, -1):
            nxt = node.next[i]
            while nxt is not None and nxt.start < start:
                node = nxt
                nxt = node.next[i]
            u[i] = node
        return u

    def advance(self, u, start):
        """Refresh a predecessor vector in place for a larger `start`.

        Lets a run of increasing gap inserts amortize to O(log F + K).
        """
        for i in range(self.level, -1, -1):
            node = u[i]
            nxt = node.next[i]
            while nxt is not None and nxt.start < start:
                node = nxt
                nxt = node.next[i]
            u[i] = node
        return u

    def floor(self, start):
        """Last fragment with start <= `start`, or None."""
        node = self.head
        for i in range(self.level, -1, -1):
            nxt = node.next[i]
            while nxt is not None and nxt.start <= start:
                node = nxt
                nxt = node.next[i]
        return node if node is not self.head else None

    def first(self):
        return self.head.next[0]

    def insert(self, start, end, data, capture, u=None):
        if u is None:
            u = self.predecessors(start)
        level = self._random_level()
        if level > self.level:
            for i in range(self.level + 1, level + 1):
                u[i] = self.head
            self.level = level
        node = _Frag(start, end, data, capture, level)
        for i in range(level + 1):
            node.next[i] = u[i].next[i]
            u[i].next[i] = node
        return node

    def trim_below(self, boundary):
        """Forget every retained byte below `boundary` (ACK reclamation).

        Removes the whole prefix of fragments ending at or below the
        boundary in O(log F + K) and cuts a straddling fragment's prefix
        in place; bytes at or above the boundary stay comparable.
        """
        head = self.head
        stop = head.next[0]
        while stop is not None and stop.end <= boundary:
            stop = stop.next[0]
        limit = stop.start if stop is not None else None
        for i in range(self.level, -1, -1):
            node = head
            nxt = node.next[i]
            while nxt is not None and (limit is None or nxt.start < limit):
                node = nxt
                nxt = node.next[i]
            head.next[i] = nxt
        if stop is not None and stop.start < boundary:
            stop.data = stop.data[boundary - stop.start:]
            stop.start = boundary


def _touching(idx, pos):
    """First fragment whose end lies beyond `pos` (overlap or successor)."""
    node = idx.floor(pos)
    if node is not None:
        return node if node.end > pos else node.next[0]
    return idx.first()


class _Flow:
    """Per-flow reassembly state; logical zero is the first payload octet."""

    __slots__ = ('isn', 'ref', 'emitted', 'acked', 'forgotten', 'fin',
                 'max_end', 'status', 'index')

    def __init__(self, isn, index):
        self.isn = isn         # raw uint32 wire ISN
        self.ref = 0           # unwrap anchor: max observed data-end/FIN+1/ACK
        self.emitted = 0       # length of the contiguous emitted prefix
        self.acked = 0         # cumulative ACK maximum (wire coordinate)
        self.forgotten = 0     # reclaimed-history boundary
        self.fin = None        # logical FIN position == payload length, or None
        self.max_end = 0       # highest observed payload end
        self.status = 'active'
        self.index = index     # _Index of retained fragments, dropped at the end


class Assembler:
    """Reassemble ordered payload bytes from capture rows (see CONTRACT.md).

    feed(row) returns a list of events (data/complete/aborted); finish()
    seals the assembler and returns one gap report per unfinished flow in
    lexicographic flow order.
    """

    def __init__(self):
        self._flows = {}
        self._sealed = False
        self._failed = False
        # Shapes the skip lists only; every emitted result is deterministic.
        self._rng = random.Random(0x5EED)

    def feed(self, row):
        if self._failed:
            raise CaptureConflict('assembler is permanently failed')
        if self._sealed:
            self._failed = True
            raise CaptureConflict('feed after finish')
        try:
            return self._feed(row)
        except CaptureConflict:
            self._failed = True
            raise

    def finish(self):
        if self._failed:
            raise CaptureConflict('assembler is permanently failed')
        if self._sealed:
            self._failed = True
            raise CaptureConflict('finish called after finish')
        self._sealed = True
        reports = []
        for flow_id in sorted(self._flows):
            st = self._flows[flow_id]
            if st.status != 'active':
                continue
            ack_payload = st.acked if st.fin is None else min(st.acked, st.fin)
            target = max(st.max_end, st.fin or 0, ack_payload)
            holes = []
            pos = st.emitted
            node = _touching(st.index, pos)
            while node is not None and node.start < target:
                if node.start > pos:
                    holes.append([pos, node.start])
                pos = node.end
                node = node.next[0]
            if pos < target:
                holes.append([pos, target])
            reports.append({'flow': flow_id, 'emitted': st.emitted,
                            'holes': holes, 'fin': st.fin})
        return reports

    # -- row dispatch -----------------------------------------------------

    def _feed(self, row):
        kind = row['kind']
        flow_id = row['flow']
        st = self._flows.get(flow_id)
        if st is None:
            if kind != 'syn':
                raise CaptureConflict(
                    f'first row for flow {flow_id!r} is not SYN')
            self._flows[flow_id] = _Flow(row['seq'], _Index(self._rng))
            return []
        if st.status != 'active':
            return []  # completed/aborted flows ignore every later row
        if kind == 'syn':
            if row['seq'] != st.isn:
                raise CaptureConflict(
                    f'flow {flow_id!r}: repeated SYN with a different ISN')
            return []
        if kind == 'data':
            return self._data(st, flow_id, row)
        if kind == 'fin':
            return self._fin(st, flow_id, row)
        if kind == 'ack':
            self._ack(st, flow_id, row)
            return []
        if kind == 'rst':
            st.status = 'aborted'
            st.index = None
            return [{'type': 'aborted', 'flow': flow_id, 'offset': st.emitted}]
        raise CaptureConflict(f'flow {flow_id!r}: unknown row kind {kind!r}')

    @staticmethod
    def _unwrap(st, seq):
        """Map a uint32 wire sequence number to its logical coordinate.

        Logical zero is ISN+1. The unambiguous capture contract keeps the
        true coordinate within 2**30 of the flow reference (the largest
        observed data-end, FIN+1 or ACK coordinate), so one uint32 multiple
        resolves it across any number of 2**32 wraps.
        """
        rel = (seq - (st.isn + 1)) % _WIRE
        return rel + _WIRE * ((st.ref - rel + _HALF) // _WIRE)

    # -- sender rows ------------------------------------------------------

    def _data(self, st, flow_id, row):
        payload = row['payload']
        start = self._unwrap(st, row['seq'])
        end = start + len(payload)
        if st.fin is not None and end > st.fin:
            raise CaptureConflict(
                f'flow {flow_id!r}: data beyond the known FIN position')
        if end > st.ref:
            st.ref = end
        if end > st.max_end:
            st.max_end = end
        lo = start if start > st.forgotten else st.forgotten
        if lo >= end:
            return []  # already reclaimed by ACKs: nothing left to compare
        idx = st.index
        capture = row['capture']
        # Pass 1: verify every retained overlapping byte and note bare gaps.
        # A differing overlap fails before this row stores or emits anything.
        gaps = []
        pos = lo
        node = _touching(idx, lo)
        while node is not None and node.start < end:
            if node.start > pos:
                gaps.append((pos, node.start))
            ov_s = node.start if node.start > lo else lo
            ov_e = node.end if node.end < end else end
            span = ov_e - ov_s
            if (node.data[ov_s - node.start:ov_s - node.start + span]
                    != payload[ov_s - start:ov_s - start + span]):
                raise CaptureConflict(
                    f'flow {flow_id!r}: retransmitted bytes differ from '
                    'retained capture')
            pos = ov_e
            node = node.next[0]
        if pos < end:
            gaps.append((pos, end))
        if not gaps:
            return []
        # Pass 2: first arrival wins — only never-captured bytes are stored.
        u = idx.predecessors(gaps[0][0])
        for gs, ge in gaps:
            idx.advance(u, gs)
            idx.insert(gs, ge, payload[gs - start:ge - start], capture, u)
        # Pass 3: emit whatever the new bytes made contiguous.
        return self._emit(st, flow_id)

    def _fin(self, st, flow_id, row):
        pos = self._unwrap(st, row['seq'])
        if st.fin is not None:
            if pos != st.fin:
                raise CaptureConflict(
                    f'flow {flow_id!r}: second FIN at a different position')
            return []  # consistent duplicate FIN is harmless
        if pos < st.max_end:
            raise CaptureConflict(
                f'flow {flow_id!r}: FIN before observed payload')
        st.fin = pos
        if pos + 1 > st.ref:
            st.ref = pos + 1
        if st.emitted == pos:
            st.status = 'complete'
            st.index = None
            return [{'type': 'complete', 'flow': flow_id, 'length': pos}]
        return []

    def _ack(self, st, flow_id, row):
        pos = self._unwrap(st, row['seq'])
        if st.fin is not None and pos > st.fin + 1:
            raise CaptureConflict(f'flow {flow_id!r}: ACK beyond FIN+1')
        if pos > st.ref:
            st.ref = pos
        if pos <= st.acked:
            return  # stale or repeated ACKs never move the boundary backward
        st.acked = pos
        boundary = st.emitted if pos > st.emitted else pos
        if st.fin is not None and boundary > st.fin:
            boundary = st.fin
        if boundary > st.forgotten:
            st.index.trim_below(boundary)
            st.forgotten = boundary

    # -- emission -----------------------------------------------------------

    def _emit(self, st, flow_id):
        idx = st.index
        pos = st.emitted
        node = _touching(idx, pos)
        if node is None or node.start != pos:
            return []
        frags = []
        while node is not None and node.start == pos:
            frags.append(node)
            pos = node.end
            node = node.next[0]
        parts = []
        sources = []
        for frag in frags:
            parts.append(frag.data)
            if sources and sources[-1]['capture'] == frag.capture:
                sources[-1]['length'] += frag.end - frag.start
            else:
                sources.append({'offset': frag.start,
                                'length': frag.end - frag.start,
                                'capture': frag.capture})
        st.emitted = pos
        events = [{'type': 'data', 'flow': flow_id, 'offset': frags[0].start,
                   'payload': b''.join(parts), 'sources': sources}]
        if st.fin is not None and pos == st.fin:
            st.status = 'complete'
            st.index = None
            events.append(
                {'type': 'complete', 'flow': flow_id, 'length': st.fin})
        return events
