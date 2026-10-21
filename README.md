# ISC DHCP checksum offloading on OpenBSD

Patches for ISC DHCP 4.4.3-P1 to handle OpenBSD checksum offloading without
changing the kernel or disabling offloading.

## Problem

On OpenBSD 7.5 and later, ISC DHCP can log `5 bad udp checksums in 5 packets`
when receiving packets through BPF with checksum offloading enabled.
Outgoing relay replies can also appear in the capture before hardware fills
their UDP checksums.

The patches:

- Honor verified inbound IPv4 and UDP checksum flags independently.
- Exclude outgoing captures using `BIOCSDIRFILT` and `BPF_DIRECTION_OUT`.
- Retain software validation for unmarked packets and all length checks.

The changes affect `common/bpf.c`, `common/packet.c`, and `includes/dhcpd.h`.
The existing decoder API remains available. OpenBSD's base `dhcpd` is a
separate implementation; these patches target the `net/isc-dhcp` port.

## Build

Use a clean ports tree matching the target OpenBSD release. With this checkout
at `/root/dhcpd`, apply the patches to the ISC DHCP port:

```sh
cd /usr/ports/net/isc-dhcp
tar -czf /root/isc-dhcp-port-backup.tgz Makefile patches
cp /root/dhcpd/patches/patch-* patches/
# Set REVISION to a value higher than the installed package's revision.
make checksum
make patch
env SUBPACKAGE=-main make subpackage
```

The [p6 release](https://github.com/ngustas/isc-dhcpd-openbsd-offload/releases/tag/openbsd-7.9-p6)
includes a rebuilt **OpenBSD 7.9 amd64** server package and SHA-256 checksums.
Do not install that binary on other releases or architectures.

Back up configuration and leases before replacing a package. Preserve service
flags, especially a custom `-lf` lease path. Local packages require
`pkg_add -D unsigned`; replacing the same version also requires `-D installed`.
Restart and verify one failover peer at a time. Future package updates may
replace the patched binary.

## Verify

With Python 3.10+, a C compiler, and `patch` installed:

```sh
python3 prepare.py
python3 test_checksums.py
```

The generator verifies the upstream source hash before extracting files.
The harness applies the distributed patches to pristine source and runs 100
checks against the actual ISC receive and decoder functions. These cover
offload flags, bad unmarked checksums, truncated packets, multiple BPF records,
and legacy behavior. It passes on Linux/WSL and native OpenBSD 7.9 headers.

Direct and simulated-relay DHCP exchanges were tested separately, alongside
live VMXNET3 captures. Patched peers served ACKs without new checksum warnings
and recovered normal/normal failover. The harness itself does not test failover.

For development, use `ruff check .`, `ruff format --check .`, and
`git diff --check`. Text files use LF, no trailing whitespace, and one final
newline. Zero-context patches target the verified upstream source exactly.

## License

[MPL-2.0](LICENSE), with upstream per-file notices retained. The release
includes the original ISC source archive; apply the patches to reconstruct
the modified source used for the package.
