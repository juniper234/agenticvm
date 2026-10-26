import struct
import unittest
import zlib

from agenticvm.png_evidence import png_signal


def fixture(rgb):
    def chunk(kind, value):
        return struct.pack(">I", len(value)) + kind + value + struct.pack(">I", zlib.crc32(kind + value) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress((b"\0" + bytes(rgb) * 2) * 2)) + chunk(b"IEND", b"")


class PaintedDisplayTests(unittest.TestCase):
    def test_black_frame_is_not_painted(self):
        self.assertEqual(png_signal(fixture((0, 0, 0)))["nonblack_pixels"], 0)

    def test_actual_color_pixels_are_counted(self):
        self.assertEqual(png_signal(fixture((10, 20, 30)))["nonblack_pixels"], 4)

    def test_corrupt_image_is_not_evidence(self):
        data = bytearray(fixture((10, 20, 30)))
        data[-5] ^= 1
        with self.assertRaises(ValueError):
            png_signal(bytes(data))
