"""Demonstration of reassembly.Assembler on the public capture fixtures.

Run as `python3 demo.py`. Standard library only.
"""

import time

from fixtures import packet, reversed_packets, small
from reassembly import Assembler, CaptureConflict


def show_events(events, indent='    '):
    for ev in events:
        if ev['type'] == 'data':
            print('%sdata     flow=%s offset=%d payload=%r sources=%s'
                  % (indent, ev['flow'], ev['offset'], ev['payload'],
                     ev['sources']))
        elif ev['type'] == 'complete':
            print('%scomplete flow=%s length=%d'
                  % (indent, ev['flow'], ev['length']))
        elif ev['type'] == 'aborted':
            print('%saborted  flow=%s emitted-prefix=%d'
                  % (indent, ev['flow'], ev['offset']))


def demo_small():
    print('== small(): FIN arrives before the missing prefix; '
          'duplicate capture 3 never wins provenance')
    a = Assembler()
    for row in small():
        events = a.feed(row)
        print('  feed %-4s seq=%-10d capture=%d -> %d event(s)'
              % (row['kind'], row['seq'], row['capture'], len(events)))
        show_events(events)
    print('  finish:', a.finish())


def demo_bulk():
    n = 10000
    rows = reversed_packets(n)
    a = Assembler()
    starts = time.perf_counter()
    events = 0
    emitted = 0
    for row in rows:
        for ev in a.feed(row):
            events += 1
            if ev['type'] == 'data':
                emitted += len(ev['payload'])
    reports = a.finish()
    dt = time.perf_counter() - starts
    print('== reversed_packets(%d): %d rows -> %d event(s), %d payload bytes, '
          '%.3fs' % (n, len(rows), events, emitted, dt))
    print('  finish:', reports)


def demo_holes():
    print('== out-of-order captures leave exact holes in the finish report')
    a = Assembler()
    a.feed(packet('g', 'syn', 0, b'', 1))
    a.feed(packet('g', 'data', 1, b'AB', 2))
    a.feed(packet('g', 'data', 6, b'FG', 3))
    a.feed(packet('g', 'data', 10, b'JK', 4))
    print('  finish:', a.finish())


def demo_conflict():
    print('== a differing retransmission fails the assembler permanently')
    a = Assembler()
    a.feed(packet('c', 'syn', 0, b'', 1))
    a.feed(packet('c', 'data', 1, b'ABCD', 2))
    try:
        a.feed(packet('c', 'data', 3, b'CX', 3))
    except CaptureConflict as exc:
        print('  CaptureConflict:', exc)
    try:
        a.finish()
    except CaptureConflict as exc:
        print('  finish also raises CaptureConflict:', exc)


def main():
    demo_small()
    demo_bulk()
    demo_holes()
    demo_conflict()
    print('DEMO_OK')


if __name__ == '__main__':
    main()
