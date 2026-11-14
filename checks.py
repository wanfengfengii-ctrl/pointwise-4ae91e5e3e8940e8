import json,sys
from fixtures import small,reversed_packets,serializable
rows=small();assert len(rows)==6
assert rows[0]['seq']==2**32-4 and rows[1]['seq']==2
assert rows[1]['payload']==rows[2]['payload']==b'world'
assert rows[4]['seq']==2**32-3 and rows[4]['payload']==b'hello'
bulk=reversed_packets(4,3)
assert [r['capture'] for r in bulk]==list(range(6))
assert [r['seq'] for r in bulk[1:5]]==[133,130,127,124]
assert [r['payload'] for r in bulk[1:5]]==[b'\x03'*3,b'\x02'*3,b'\x01'*3,b'\x00'*3]
print('CAPTURE_ROWS_BASELINE_OK')
if len(sys.argv)>1:print(json.dumps(serializable(rows)))
