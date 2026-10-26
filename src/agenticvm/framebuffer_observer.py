"""Read-only RFB framebuffer observer. Sends format/encoding/update requests only."""
import socket,struct,zlib

def take(stream,count):
    if not 0<=count<=16*1024**2: raise ValueError('RFB field exceeds observation bound')
    data=bytearray()
    while len(data)<count:
        part=stream.recv(count-len(data))
        if not part: raise EOFError('RFB stream ended')
        data.extend(part)
    return bytes(data)

def png(width,height,rgb):
    def chunk(kind,data): return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data))
    pixels=b''.join(b'\0'+rgb[y*width*3:(y+1)*width*3] for y in range(height))
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',width,height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(pixels))+chunk(b'IEND',b'')

def capture(port,path):
    sent=[]
    with socket.create_connection(('127.0.0.1',port),timeout=10) as stream:
        version=take(stream,12)
        if version!=b'RFB 003.008\n': raise ValueError('Unexpected local RFB version')
        stream.sendall(version)
        count=take(stream,1)[0];types=take(stream,count)
        if 1 not in types: raise ValueError('Owned local framebuffer did not offer no-auth access')
        stream.sendall(b'\x01')
        if take(stream,4)!=b'\0'*4: raise ValueError('Owned framebuffer handshake failed')
        stream.sendall(b'\x01')
        width,height=struct.unpack('!HH',take(stream,4));take(stream,16)
        name=take(stream,struct.unpack('!I',take(stream,4))[0])
        if not (1<=width<=2048 and 1<=height<=1536): raise ValueError('Framebuffer size exceeds bound')
        fmt=struct.pack('!BBBBHHHBBBxxx',32,24,0,1,255,255,255,16,8,0)
        stream.sendall(b'\0\0\0\0'+fmt);sent.append(0)
        stream.sendall(struct.pack('!BBHi',2,0,1,0));sent.append(2)
        stream.sendall(struct.pack('!BBHHHH',3,0,0,0,width,height));sent.append(3)
        if take(stream,1)!=b'\0': raise ValueError('Unexpected framebuffer message')
        padding,rectangles=struct.unpack('!BH',take(stream,3))
        if not 1<=rectangles<=256: raise ValueError('Framebuffer rectangle bound exceeded')
        rgb=bytearray(width*height*3)
        for _ in range(rectangles):
            x,y,w,h,encoding=struct.unpack('!HHHHi',take(stream,12))
            if encoding!=0 or x+w>width or y+h>height: raise ValueError('Unexpected framebuffer encoding/bounds')
            raw=take(stream,w*h*4)
            for row in range(h):
                source=raw[row*w*4:(row+1)*w*4];target=((y+row)*width+x)*3
                output=bytearray(w*3);output[0::3]=source[2::4];output[1::3]=source[1::4];output[2::3]=source[0::4]
                rgb[target:target+w*3]=output
    path.write_bytes(png(width,height,bytes(rgb)))
    return {'width':width,'height':height,'name':name.decode(errors='replace'),
        'rfb_client_message_types_sent':sent,'keyboard_pointer_clipboard_messages_sent':False}
