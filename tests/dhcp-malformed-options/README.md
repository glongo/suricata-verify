# DHCP malformed and truncated options

This test verifies that DHCP option parsing errors are classified according to
whether sufficient data is present.

`input.pcap` contains four DHCP ACKs. Packets 1 and 2 exercise the primary DHCP
option stream: packet 1 contains an option 51 value with an invalid declared
length despite having enough value bytes, while packet 2 contains an option 12
that declares five data bytes when only two remain in the UDP payload. Packets
3 and 4 carry malformed options in overloaded `sname` and `file` fields. The
option in `file` declares data beyond the boundary of that fixed-size field.

After the parser fix, packets 1, 3, and 4 raise `dhcp.malformed_options`, while
only packet 2 raises `dhcp.truncated_options`.

The capture is generated deterministically with Scapy:

```sh
./create.py
```
