"""Compile real ISC decoder/BPF receive functions in a small test harness.

Run with python3 under Linux/WSL or OpenBSD. This does not replace a port build.
"""

import ctypes as C
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
IP_OK, UDP_OK = 0x0008, 0x0080  # OpenBSD sys/sys/mbuf.h
IP_BAD, UDP_BAD = 0x0010, 0x0100

PREAMBLE = r"""
#define _DEFAULT_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#define log_info(...) ((void)0)
#define log_debug(...) ((void)0)
#define M_IPV4_CSUM_IN_OK 0x0008
#define M_UDP_CSUM_IN_OK 0x0080
#define BPF_WORDALIGN(n) (((n) + 3U) & ~3U)
typedef void omapi_object_t;
struct hardware { int unused; };
struct interface_info {
    int rfdesc;
    unsigned char *rbuf;
    unsigned rbuf_offset, rbuf_len, rbuf_max;
};
/* Synthetic BPF layout; the real OpenBSD ABI is checked by the port build. */
struct bpf_hdr {
    uint32_t bh_caplen, bh_datalen;
    uint16_t bh_hdrlen, bh_csumflags;
};
static void dhcp_interface_remove(omapi_object_t *a, void *b) {(void)a;(void)b;}
static ssize_t decode_hw_header(struct interface_info *a, unsigned char *b,
                               unsigned c, struct hardware *d) {
    (void)a;(void)b;(void)c;(void)d; return 14;
}
ssize_t decode_udp_ip_header_csum(struct interface_info *, unsigned char *,
    unsigned, struct sockaddr_in *, unsigned, unsigned *, int, int);
"""

ADAPTER = r"""
int run_packet(unsigned char *packet, unsigned size, unsigned flags,
               unsigned char *out, unsigned outsize) {
    union { uint64_t align; unsigned char bytes[4096]; } data;
    struct bpf_hdr hdr;
    struct interface_info iface;
    struct hardware hw;
    struct sockaddr_in from;
    memset(&hdr, 0, sizeof hdr);
    hdr.bh_hdrlen = sizeof hdr;
    hdr.bh_caplen = hdr.bh_datalen = size + 14;
    hdr.bh_csumflags = flags;
    memset(&data, 0, sizeof data);
    memcpy(data.bytes, &hdr, sizeof hdr);
    memcpy(data.bytes + sizeof hdr + 14, packet, size);
    memset(&iface, 0, sizeof iface);
    iface.rfdesc = -1;
    iface.rbuf = data.bytes;
    iface.rbuf_len = BPF_WORDALIGN(sizeof hdr + hdr.bh_caplen);
    iface.rbuf_max = sizeof data;
    return receive_packet(&iface, out, outsize, &from, &hw);
}
int run_legacy(unsigned char *packet, unsigned size, int ready) {
    struct sockaddr_in from;
    unsigned len = 0;
    return decode_udp_ip_header(NULL, packet, 0, &from, size, &len, ready);
}
int run_pair(unsigned char *first, unsigned firstsize, unsigned firstflags,
             unsigned char *second, unsigned secondsize, unsigned secondflags,
             unsigned char *out, unsigned outsize) {
    union { uint64_t align; unsigned char bytes[4096]; } data;
    struct bpf_hdr hdr;
    struct interface_info iface;
    struct hardware hw;
    struct sockaddr_in from;
    unsigned offset = BPF_WORDALIGN(sizeof hdr + 14 + firstsize);
    memset(&data, 0, sizeof data);
    memset(&hdr, 0, sizeof hdr);
    hdr.bh_hdrlen = sizeof hdr;
    hdr.bh_caplen = hdr.bh_datalen = 14 + firstsize;
    hdr.bh_csumflags = firstflags;
    memcpy(data.bytes, &hdr, sizeof hdr);
    memcpy(data.bytes + sizeof hdr + 14, first, firstsize);
    hdr.bh_caplen = hdr.bh_datalen = 14 + secondsize;
    hdr.bh_csumflags = secondflags;
    memcpy(data.bytes + offset, &hdr, sizeof hdr);
    memcpy(data.bytes + offset + sizeof hdr + 14, second, secondsize);
    memset(&iface, 0, sizeof iface);
    iface.rfdesc = -1;
    iface.rbuf = data.bytes;
    iface.rbuf_len = offset + BPF_WORDALIGN(sizeof hdr + hdr.bh_caplen);
    iface.rbuf_max = sizeof data;
    int result = receive_packet(&iface, out, outsize, &from, &hw);
    if (result <= 0)
        return -100;
    return receive_packet(&iface, out, outsize, &from, &hw);
}
"""


def checksum(data):
    data += b'\0' * (len(data) % 2)
    n = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while n >> 16:
        n = (n & 65535) + (n >> 16)
    return (~n) & 65535


def packet(payload=b'DHCP test payload', *, ip_bad=False, udp_bad=False, zero=False):
    src, dst = socket.inet_aton('10.0.0.1'), socket.inet_aton('10.0.0.2')
    length = 8 + len(payload)
    udp = struct.pack('!HHHH', 67, 67, length, 0)
    csum = checksum(src + dst + struct.pack('!BBH', 0, 17, length) + udp + payload) or 65535
    udp = struct.pack('!HHHH', 67, 67, length, 0 if zero else csum)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + length, 1, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    result = bytearray(ip + udp + payload)
    if ip_bad:
        result[10] ^= 1
    if udp_bad:
        result[26] ^= 1
    return bytes(result)


def library(directory, output, offload=True):
    text = (directory / 'common/packet.c').read_text()
    sums = text[text.index('u_int32_t checksum (') : text.index('#ifdef PACKET_ASSEMBLY')]
    decoder = text[
        text.index('ssize_t\ndecode_udp_ip_header(') : text.index('#endif /* PACKET_DECODING */')
    ]
    bpf = (directory / 'common/bpf.c').read_text()
    receiver = bpf[
        bpf.index('ssize_t receive_packet (') : bpf.index(
            '\n\n', bpf.index('\treturn (0);', bpf.index('ssize_t receive_packet ('))
        )
    ]
    # Exercise the actual OpenBSD branch without redefining the host OS for libc.
    receiver = receiver.replace(
        '#if defined(__OpenBSD__) && OpenBSD >= 202404', '#if 1' if offload else '#if 0'
    )
    preamble = PREAMBLE
    if sys.platform.startswith('openbsd'):
        # Use the kernel's real BPF record layout and checksum flag constants.
        preamble = re.sub(r'struct bpf_hdr \{.*?\};', '', preamble, flags=re.S)
        preamble = re.sub(r'#define M_(?:IPV4|UDP)_CSUM_IN_OK .*\n', '', preamble)
        preamble = re.sub(r'#define BPF_WORDALIGN\(n\).*\n', '', preamble)
        preamble = preamble.replace(
            '#include <sys/socket.h>',
            '#include <sys/socket.h>\n#include <sys/param.h>\n'
            '#include <sys/mbuf.h>\n#include <net/bpf.h>',
        )
    code = preamble + sums + decoder + receiver + ADAPTER
    cfile = output.with_suffix('.c')
    cfile.write_text(code)
    subprocess.run(
        [
            'cc',
            '-shared',
            '-fPIC',
            '-O1',
            '-g',
            '-Wall',
            '-Wextra',
            '-Wno-unused-parameter',
            '-Wno-unused-function',
            str(cfile),
            '-o',
            str(output),
        ],
        check=True,
    )
    lib = C.CDLL(str(output))
    lib.run_packet.argtypes = [C.c_void_p, C.c_uint, C.c_uint, C.c_void_p, C.c_uint]
    lib.run_packet.restype = C.c_int
    lib.run_legacy.argtypes = [C.c_void_p, C.c_uint, C.c_int]
    lib.run_legacy.restype = C.c_int
    lib.run_pair.argtypes = [
        C.c_void_p,
        C.c_uint,
        C.c_uint,
        C.c_void_p,
        C.c_uint,
        C.c_uint,
        C.c_void_p,
        C.c_uint,
    ]
    lib.run_pair.restype = C.c_int
    return lib


def main():
    count = 0
    with tempfile.TemporaryDirectory() as temp:
        applied = Path(temp) / 'applied'
        shutil.copytree(ROOT / 'upstream', applied)
        for patch in sorted((ROOT / 'patches').iterdir()):
            subprocess.run(
                ['patch', '--batch', '-p0', '-i', str(patch)],
                cwd=applied,
                check=True,
                stdout=subprocess.PIPE,
            )
        for path in ['common/bpf.c', 'common/packet.c', 'includes/dhcpd.h']:
            assert (applied / path).read_bytes() == (ROOT / 'patched' / path).read_bytes()
        old = library(ROOT / 'upstream', Path(temp) / 'old.so')
        new = library(applied, Path(temp) / 'new.so')
        compat = library(applied, Path(temp) / 'compat.so', offload=False)

        def check(lib, data, flags, accepted, payload=None):
            nonlocal count
            buf, out = C.create_string_buffer(data), C.create_string_buffer(4096)
            rc = lib.run_packet(buf, len(data), flags, out, len(out))
            assert (rc > 0) == accepted, (flags, accepted, rc)
            if accepted:
                assert out.raw[:rc] == (payload if payload is not None else data[28:])
            count += 1

        # Offload flag mapping: each OK bit suppresses only its own checksum.
        for flags in [0, IP_OK, UDP_OK, IP_OK | UDP_OK, IP_BAD, UDP_BAD]:
            for ip_bad in [False, True]:
                for udp_bad in [False, True]:
                    data = packet(ip_bad=ip_bad, udp_bad=udp_bad)
                    expected = (not ip_bad or bool(flags & IP_OK)) and (
                        not udp_bad or bool(flags & UDP_OK)
                    )
                    check(new, data, flags, expected)
                    # Reproduce the upstream bug: it ignores all receive flags.
                    check(old, data, flags, not ip_bad and not udp_bad)
                    check(compat, data, flags, not ip_bad and not udp_bad)
        for payload in [b'x', b'xy', b'x' * 301, b'x' * 302]:
            check(new, packet(payload), 0, True, payload)
        check(new, packet(zero=True), 0, True)
        check(new, packet(zero=True, ip_bad=True), 0, False)
        check(new, packet(zero=True, ip_bad=True), IP_OK, True)
        # Offloading must never bypass packet length validation.
        for flags in [0, IP_OK | UDP_OK]:
            data = packet()
            for size in [0, 19, 20, 27, len(data) - 1]:
                check(new, data[:size], flags, False)
            for length in [0, 7, 65535]:
                malformed = bytearray(data)
                malformed[24:26] = struct.pack('!H', length)
                check(new, bytes(malformed), flags, False)
        # Existing callers retain IP checking even when skipping UDP checks.
        for lib in [old, new]:
            assert (
                lib.run_legacy(C.create_string_buffer(packet(udp_bad=True)), len(packet()), 0) == 28
            )
            assert (
                lib.run_legacy(C.create_string_buffer(packet(ip_bad=True)), len(packet()), 0) == -1
            )
            count += 2
        # A verified first packet must not disable checks on the next BPF record.
        data = packet(ip_bad=True, udp_bad=True)
        out = C.create_string_buffer(4096)
        assert (
            new.run_pair(
                C.create_string_buffer(data),
                len(data),
                IP_OK | UDP_OK,
                C.create_string_buffer(data),
                len(data),
                0,
                out,
                len(out),
            )
            == 0
        )
        count += 1
    layout = (
        'native OpenBSD BPF headers'
        if sys.platform.startswith('openbsd')
        else 'synthetic BPF headers'
    )
    print(
        f'PASS: {count} receive/decoder checks, including upstream failure reproduction; {layout}'
    )


if __name__ == '__main__':
    main()
