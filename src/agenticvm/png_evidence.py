"""Bounded read-only RGB/RGBA PNG signal inspection for native display evidence."""
import struct
import zlib


def png_signal(data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) > 4 * 1024 * 1024:
        raise ValueError("Not a bounded PNG")
    offset, compressed, header = 8, bytearray(), None
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        end = offset + 8 + length
        if end + 4 > len(data):
            raise ValueError("Truncated PNG chunk")
        value = data[offset + 8:end]
        if zlib.crc32(kind + value) & 0xffffffff != struct.unpack(">I", data[end:end + 4])[0]:
            raise ValueError("PNG CRC mismatch")
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", value)
        elif kind == b"IDAT":
            compressed.extend(value)
        elif kind == b"IEND":
            break
        offset = end + 4
    if not header:
        raise ValueError("PNG lacks a header")
    width, height, depth, color, compression, filtering, interlace = header
    if depth != 8 or color not in {2, 6} or compression or filtering or interlace or not 1 <= width * height <= 4096 * 4096:
        raise ValueError("Unsupported native PNG layout")
    channels = 3 if color == 2 else 4
    stride = width * channels
    expected = (stride + 1) * height
    decoder = zlib.decompressobj()
    raw = decoder.decompress(bytes(compressed), expected + 1)
    if len(raw) != expected or not decoder.eof or decoder.unused_data:
        raise ValueError("PNG pixel extent mismatch")
    previous = bytearray(stride)
    visible = 0
    for y in range(height):
        start = y * (stride + 1)
        mode = raw[start]
        if mode > 4:
            raise ValueError("Unknown PNG filter")
        row = bytearray(raw[start + 1:start + 1 + stride])
        for i in range(stride):
            left = row[i - channels] if i >= channels else 0
            above = previous[i]
            upper_left = previous[i - channels] if i >= channels else 0
            if mode == 1:
                prediction = left
            elif mode == 2:
                prediction = above
            elif mode == 3:
                prediction = (left + above) // 2
            elif mode == 4:
                p = left + above - upper_left
                a, b, c = abs(p - left), abs(p - above), abs(p - upper_left)
                prediction = left if a <= b and a <= c else above if b <= c else upper_left
            else:
                prediction = 0
            row[i] = (row[i] + prediction) & 255
        visible += sum(bool(row[i] or row[i + 1] or row[i + 2]) and (channels == 3 or row[i + 3] != 0) for i in range(0, stride, channels))
        previous = row
    return {"width": width, "height": height, "nonblack_pixels": visible, "pixels": width * height}
