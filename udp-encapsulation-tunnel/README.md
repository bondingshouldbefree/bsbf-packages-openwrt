# UDP Encapsulation Tunnel Logic

- Configuration options; interface, listen-port, and bind-to-interface options are mandatory:

```
--interface tun0
--listen-port 12345
--bind-to-interface wwan1
--endpoint-port 12345

sudo ./udp-encapsulation-tunnel --interface tun0 --listen-port 12345 --bind-to-interface eth0 --endpoint-port 12345
```

- Tunnel programme binds to the interface described on bind-to-interface and listens on UDP port described on listen-port.

## Data RX Path

- Incoming IPv4 packet on bound interface destined to the listened UDP port is delivered to tunnel programme.
- If EndpointPort is not defined, store the IPv4 saddr, UDP sport, and TCP sport of the packet to a variable called "store". These three form an entry. There can be multiple entries with the same IPv4 saddr, UDP sport, or TCP sport.
- Tunnel programme takes the IPv4 payload, removes the UDP header. Sends it as an incoming IPv4 packet on the tunnel interface.
  - IPv4 header details:
    - saddr: IPv4 saddr on the packet delivered to tunnel programme.
    - daddr: First found IPv4 address assigned to the tunnel interface.
    - Protocol: TCP.

## Data TX Path

- Outgoing IPv4 packet on tunnel interface (tun) is delivered to tunnel programme.
- Discard the packet if it's not a TCP packet.
- If EndpointPort is not defined, look for an entry on the "store" variable by using the IPv4 daddr and TCP dport on this packet. If there isn't an entry found, discard the packet.
- Tunnel programme takes the IPv4 payload, encapsulates it in UDP. Sends it as an outgoing IPv4 packet on the bound interface.
  - IPv4 header details:
    - saddr: First found IPv4 address assigned to the bound interface.
    - daddr: IPv4 daddr on the packet delivered to tunnel programme.
    - Protocol: UDP.
  - UDP header details:
    - sport: Port defined on the ListenPort option.
    - dport:
      - If EndpointPort is not defined, UDP port on the "store" variable found from IPv4 daddr and TCP dport on the packet delivered to tunnel programme.
      - Else, port defined on the EndpointPort option.
