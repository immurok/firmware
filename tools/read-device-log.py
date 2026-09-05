#!/usr/bin/env python3
"""把 CH592F 的 release-debug 日志从 USB CDC 口抄到文件。

设备日志走 /dev/cu.usbmodem*（不是 wchusbserial —— 那个是烧录器，读 0 字节）。
macOS 没有 timeout(1)，所以用 select 轮询而不是阻塞读。

用法: read-device-log.py [/dev/cu.usbmodemXXX] [输出文件]
      不给参数就自动找第一个 usbmodem 口，输出到 stdout。
"""
import glob
import os
import select
import sys
import termios


def open_port(port):
    fd = os.open(port, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
    a = termios.tcgetattr(fd)
    a[0] = termios.IGNBRK          # iflag
    a[1] = 0                       # oflag
    a[3] = 0                       # lflag: raw
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL   # cflag
    a[4] = a[5] = termios.B115200  # ispeed / ospeed
    termios.tcsetattr(fd, termios.TCSANOW, a)
    return fd


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else None
    if not port:
        found = sorted(glob.glob("/dev/cu.usbmodem*"))
        if not found:
            sys.stderr.write("找不到 /dev/cu.usbmodem*\n")
            return 1
        port = found[0]

    out = open(sys.argv[2], "wb", buffering=0) if len(sys.argv) > 2 else sys.stdout.buffer
    fd = open_port(port)
    sys.stderr.write(f"reading {port} @115200\n")
    try:
        while True:
            if select.select([fd], [], [], 1.0)[0]:
                data = os.read(fd, 4096)
                if data:
                    out.write(data)
                    if out is not sys.stdout.buffer:
                        pass
                    else:
                        out.flush()
    except KeyboardInterrupt:
        pass
    finally:
        os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
