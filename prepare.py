"""Fetch verified ISC 4.4.3-P1 source and generate OpenBSD ports patches."""

import difflib
import hashlib
import io
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
URL = 'https://ftp.isc.org/isc/dhcp/4.4.3-P1/dhcp-4.4.3-P1.tar.gz'
SHA256 = '0ac416bb55997ca8632174fd10737fd61cdb8dba2752160a335775bc21dc73c7'


def main():
    archive = ROOT / 'dhcp-4.4.3-P1.tar.gz'
    data = archive.read_bytes() if archive.exists() else urllib.request.urlopen(URL).read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('Source hash mismatch')
    archive.write_bytes(data)
    paths = ['common/bpf.c', 'common/packet.c', 'includes/dhcpd.h']
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        originals = {p: tar.extractfile('dhcp-4.4.3-P1/' + p).read().decode() for p in paths}
    changed = dict(originals)
    changed['common/bpf.c'] = changed['common/bpf.c'].replace(
        '#include "dhcpd.h"\n',
        '#include "dhcpd.h"\n#ifdef __OpenBSD__\n#include <sys/param.h>\n#include <sys/mbuf.h>\n#endif\n',
        1,
    )
    marker = '\tint b;\n'
    assert marker in changed['common/bpf.c']
    changed['common/bpf.c'] = changed['common/bpf.c'].replace(
        marker, marker + '#ifdef __OpenBSD__\n\tu_int dirfilt = BPF_DIRECTION_OUT;\n#endif\n', 1
    )
    marker = '\n\tget_hw_addr(info->name, &info->hw_address);'
    assert marker in changed['common/bpf.c']
    changed['common/bpf.c'] = changed['common/bpf.c'].replace(
        marker,
        """
#ifdef __OpenBSD__
\t/* Ignore our own relay replies before transmit checksum completion. */
\tif (ioctl(sock, BIOCSDIRFILT, &dirfilt) < 0)
\t\tlog_fatal("Can't filter outgoing BPF packets on %s: %m",
\t\t          info->name);
#endif
"""
        + marker,
        1,
    )
    old = """\t\t/* Decode the IP and UDP headers... */
\t\toffset = decode_udp_ip_header(interface, interface->rbuf,
\t\t\t\t\t      interface->rbuf_offset,
                                              from, hdr.bh_caplen, &paylen, 1);"""
    new = """\t\t/* Decode the IP and UDP headers... */
#if defined(__OpenBSD__) && OpenBSD >= 202404
\t\t/* BPF carries the kernel's checksum-offload results. */
\t\toffset = decode_udp_ip_header_csum(interface, interface->rbuf,
\t\t    interface->rbuf_offset, from, hdr.bh_caplen, &paylen,
\t\t    (hdr.bh_csumflags & M_IPV4_CSUM_IN_OK) == 0,
\t\t    (hdr.bh_csumflags & M_UDP_CSUM_IN_OK) == 0);
#else
\t\toffset = decode_udp_ip_header(interface, interface->rbuf,
\t\t\t\t\t      interface->rbuf_offset,
                                              from, hdr.bh_caplen, &paylen, 1);
#endif"""
    assert old in changed['common/bpf.c']
    changed['common/bpf.c'] = changed['common/bpf.c'].replace(old, new, 1)
    old = """     unsigned *rbuflen, int csum_ready)
{"""
    # Keep the existing entry point and its Boolean UDP argument unchanged for
    # Linux LPF, other BPF platforms, and every other existing caller.
    wrapper = """     unsigned *rbuflen, int csum_ready)
{
  return decode_udp_ip_header_csum(interface, buf, bufix, from, buflen,
                                  rbuflen, 1, csum_ready);
}

/* Non-zero *_csum_ready arguments request software checksum validation.
 * A caller may skip either checksum only when its receive API validates it.
 * Packet length checks remain unconditional.
 */
ssize_t
decode_udp_ip_header_csum(struct interface_info *interface,
                         unsigned char *buf, unsigned bufix,
                         struct sockaddr_in *from, unsigned buflen,
                         unsigned *rbuflen, int ip_csum_ready,
                         int udp_csum_ready)
{"""
    assert old in changed['common/packet.c']
    changed['common/packet.c'] = changed['common/packet.c'].replace(old, wrapper, 1)
    changed['common/packet.c'] = changed['common/packet.c'].replace(
        'if (wrapsum (checksum (buf + bufix, ip_len, 0))) {',
        'if (ip_csum_ready && wrapsum (checksum (buf + bufix, ip_len, 0))) {',
        1,
    )
    changed['common/packet.c'] = changed['common/packet.c'].replace(
        'if (udp.uh_sum && csum_ready) {', 'if (udp.uh_sum && udp_csum_ready) {', 1
    )
    declaration = """ssize_t decode_udp_ip_header_csum(struct interface_info *, unsigned char *,
                                  unsigned, struct sockaddr_in *,
                                  unsigned, unsigned *, int, int);

"""
    marker = '/* ethernet.c */'
    assert marker in changed['includes/dhcpd.h']
    changed['includes/dhcpd.h'] = changed['includes/dhcpd.h'].replace(
        marker, declaration + marker, 1
    )
    for path in paths:
        for directory, content in [('upstream', originals[path]), ('patched', changed[path])]:
            dest = ROOT / directory / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding='utf-8', newline='\n')
        patch = ''.join(
            difflib.unified_diff(
                originals[path].splitlines(True),
                changed[path].splitlines(True),
                n=0,
                fromfile=path + '.orig',
                tofile=path,
            )
        )
        dest = ROOT / 'patches' / ('patch-' + path.replace('/', '_').replace('.', '_'))
        dest.parent.mkdir(exist_ok=True)
        dest.write_text(patch, encoding='utf-8', newline='\n')
    print('Verified upstream SHA-256:', hashlib.sha256(data).hexdigest())
    print('Generated three patches in', ROOT / 'patches')


if __name__ == '__main__':
    main()
