# One-way TCP payload capture rows

This is a data-acquisition stage after packet decoding. fixtures.py contains
actual sequence-number/payload capture rows and a bulk producer, no reassembler.
No sockets, IP/TCP parsing, checksum verification or retransmission sender.
The upstream decoder has removed options and split SYN/FIN from data. A row is:
 {flow: str, kind: syn|data|ack|fin|rst, seq: uint32, payload: bytes, capture: int}.
capture is the unique increasing capture-row number; flow identifies a connection
generation and one sender direction, already assigned upstream. ack rows are
receiver cumulative acknowledgments of that sender, with seq=next expected wire
sequence. Other rows are sender sequence positions. SYN/FIN each consumes one
wire sequence; data rows never carry SYN/FIN. Non-data payloads are empty.
The first row for every flow is SYN. Repeated SYN must carry the same ISN;
a different ISN for an existing flow is an error. No flow-ID reuse.

## Requested public interface
reassembly.Assembler().feed(row) returns a list of events; finish() returns a list
of gap reports in lexicographic flow order and seals the assembler.
data event: {type:'data', flow:str, offset:int, payload:bytes,
             sources:[{offset:int,length:int,capture:int}, ...]}.
offset zero is ISN+1, the first payload octet. Emit each contiguous captured byte
exactly once, in sender order; never leap over a hole. Event chunk boundaries
are implementation choices, but each event's sources fully partition its payload
into absolute half-open source runs; preserve the capture number of the first
row that supplied each byte. Coalesce adjacent source runs with the same capture.
Do not invent bytes based on receiver ACKs.
complete event: {type:'complete',flow:str,length:int}. Emit exactly once when a
FIN is captured and every payload byte preceding it has been emitted. FIN itself
is not payload. A FIN may arrive before a missing data segment. A consistent
duplicate FIN is harmless; a second FIN at a different logical position is error.
rst event aborts an unfinished flow: return {type:'aborted',flow:str,offset:int}
where offset is the already emitted prefix length. Drop its buffered state.
Ignore all later rows for complete/aborted flows. For active flows, data after
the known FIN position, ACK beyond FIN+1, or FIN before observed payload is error.

Wire sequence numbers wrap at 2**32, and streams may cross multiple wraps
(up to 2**40 payload octets). At each row, its true logical data/FIN position or
ACK coordinate is within 2**30 of the largest previously observed logical
data-end, FIN+1, ACK coordinate or zero, whichever is largest. This is the
unambiguous capture contract, not an input to the assembler: only uint32 is given.
Coordinates can be negative only for retransmitted SYN, which is a separate row.
ACK's logical wire coordinate counts the FIN if present; payload trimming cannot
discard an uncaptured gap. ACK coordinates are cumulative maxima: stale ACKs
cannot move the acknowledgment boundary backward. Data-end is payload-start+len.

For overlapping data, verify bytes against all retained overlapping bytes;
equal retransmissions produce no duplicate data. A differing overlap raises
reassembly.CaptureConflict before emitting any bytes from that row and permanently
fails the entire assembler. For first-arrival provenance, earlier bytes always
win even where equal overlaps partially extend the capture.
ACK permits forgetting emitted history strictly below its payload boundary:
drop emitted bytes below min(ACK, emitted-prefix), with FIN clamped to its payload
position. Ignore comparisons for a later duplicate's already forgotten prefix,
but process/verify its remaining bytes. Without ACK, emitted bytes remain for
conflict checking. Out-of-order, ACK, FIN and overlap responsibilities must work
together; memory reclamation cannot invalidate still-buffered gap-filling bytes.

finish seals input and returns one report for every uncompleted/unaborted flow:
 {flow, emitted:int, holes:[[start,end],...], fin:int|None}.
Let target=max(highest observed payload end, known FIN position, ACK payload
boundary). holes are the maximal missing half-open intervals in [emitted,target);
known buffered bytes split holes and are never themselves reported missing.
No FIN still needs a report even when there are zero holes. finish does not
convert a gap or missing FIN into a successful completion. Later feed/finish
raises CaptureConflict. Protocol/state errors described above use the same
permanent failure. Valid field types and first-SYN presence are guaranteed.

Memory after each feed: retained payload octets only for unacknowledged emitted
history plus un-emitted unique captured bytes. Do not retain whole prior rows,
duplicate byte copies or already trimmed payload backing stores. Metadata is
O(live disjoint first-arrival source fragments + flows); no Python object or
mapping entry per byte. Returned events/caller-owned rows are excluded.
For P packets and F live fragments, use an interval index with O(log(F+1)+K)
expected/amortized search/update cost, where K is actually touched overlapping
fragments; do not linearly scan/rebuild/shift every live fragment per packet.
Payload copying/comparison costs may scale with actual bytes processed.
The reversed_packets generator gives a worst-case disorder example, not the
only benchmark. No persistence, concurrency, full TCP stack or arbitrary stale
retransmissions outside the unambiguous capture window.

small() produces bytes b'helloworld' with offsets 0..10; first five octets come
from capture 5, last five from capture 2, then one complete length 10. Its
duplicate capture 3 never wins provenance. FIN arrives before the missing prefix.
Keep fixtures.py and checks.py; add the receiver, independent business checks
and actual demonstration, and update the existing runtime manifest accordingly.
