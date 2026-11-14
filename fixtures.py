"""Public capture-row fixtures, not a TCP reassembler."""
import base64,json
def packet(flow,kind,seq=0,payload=b'',capture=0):
    return {'flow':flow,'kind':kind,'seq':seq,'payload':payload,'capture':capture}
def small():
    isn=2**32-4
    return [packet('a','syn',isn,capture=1),
      packet('a','data',2,b'world',2),
      packet('a','data',2,b'world',3),
      packet('a','fin',7,capture=4),
      packet('a','data',2**32-3,b'hello',5),
      packet('a','ack',8,capture=6)]
def reversed_packets(n=10000,width=32):
    """One producer with reversed delivery; no assembler or ordering index."""
    isn=123;out=[packet('r','syn',isn,capture=0)]
    for i in range(n-1,-1,-1):
        out.append(packet('r','data',(isn+1+i*width)%2**32,bytes([i%251])*width,n-i))
    out.append(packet('r','fin',(isn+1+n*width)%2**32,capture=n+1))
    return out
def serializable(rows):
    return [{**r,'payload':base64.b64encode(r['payload']).decode()} for r in rows]
