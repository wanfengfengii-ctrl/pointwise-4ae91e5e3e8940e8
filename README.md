# TCP capture rows

`fixtures.py` holds the public capture-row samples and the bulk producer;
`checks.py` is the preserved fixture regression (`python3 checks.py`, or
`python3 checks.py demo` to print the rows as JSON).

`reassembly.py` is the receiver requested in CONTRACT.md:
`Assembler().feed(row)` turns capture rows into ordered `data` / `complete`
/ `aborted` events with first-capture provenance, and `finish()` seals the
assembler and reports exact holes for every unfinished flow. It unwraps
uint32 wire sequences across multiple 2**32 wraps, verifies overlapping
retransmissions (raising `CaptureConflict` on differing bytes), reclaims
ACKed history, and indexes retained fragments in a skip list. Standard
library only; no sockets or TCP stack.

`business_checks.py` verifies the receiver: the preserved baseline,
deterministic contract checks, and a seeded randomized differential test
against a naive model (`python3 business_checks.py`).

`demo.py` demonstrates the receiver on the fixtures, a worst-case reversed
stream, gap reporting, and permanent conflict failure (`python3 demo.py`).
