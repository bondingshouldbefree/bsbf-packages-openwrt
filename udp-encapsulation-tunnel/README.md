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
- If EndpointPort is not defined, generate a unique IPv4 address from the IPv4 saddr and UDP sport of the packet and store these three as an entry on the "connection_store" structure. There can only be a single entry with the same IPv4 saddr and UDP sport. Remove the entry if it wasn't attempted to be stored in 5 minutes.
- Tunnel programme takes the UDP payload, creates an IPv4 header and puts it on top of the UDP payload. Writes the result to the tunnel interface.
  - IPv4 header details:
    - saddr:
      - If EndpointPort is not defined, IPv4 addr generated from the IPv4 saddr and UDP sport of the packet delivered to tunnel programme.
      - Else, IPv4 saddr on the packet delivered to tunnel programme.
    - daddr: First found IPv4 address assigned to the tunnel interface.
    - Protocol: TCP.

## Data TX Path

- Outgoing IPv4 packet on tunnel interface (tun) is delivered to tunnel programme.
- Discard the packet if it's not a TCP packet or if the IP header length is more than 20 bytes.
- If EndpointPort is not defined, look for an entry on the "connection_store" structure by using the IPv4 daddr on this packet. If there isn't an entry found, discard the packet.
- Tunnel programme removes the IPv4 header from the IPv4 packet. Sends it as an outgoing UDP packet on the bound interface.
  - IPv4 header details:
    - saddr: Decided by kernel by consulting the relevant routing table.
    - daddr:
      - If EndpointPort is not defined, IPv4 addr on the "connection_store" structure found from IPv4 daddr on the packet delivered to tunnel programme.
      - Else, IPv4 daddr on the packet delivered to tunnel programme.
  - UDP header details:
    - sport: Decided by kernel, which is the port defined on the ListenPort option.
    - dport:
      - If EndpointPort is not defined, UDP port on the "connection_store" structure found from IPv4 daddr on the packet delivered to tunnel programme.
      - Else, port defined on the EndpointPort option.

---

# Future Logic With Authentication

## Authentication

- If EndpointPort is not defined:
  - Listen on TCP at ListenPort and wait for remote peers to initiate authentication.
  - If successfully authenticated, generate a unique IPv4 address from the IPv4 saddr and UDP sport of the remote peer and store these three as an entry on the "connection_store" structure. There can only be a single entry with the same IPv4 saddr and UDP sport. Remove the entry if it wasn't attempted to be stored in 5 minutes.
  - Else, end TCP connection.

## Data RX Path

- Incoming IPv4 packet on bound interface destined to the listened UDP port is delivered to tunnel programme.
- If EndpointPort is not defined, look for an entry on the "connection_store" structure by using the IPv4 saddr and UDP sport on this packet. If there isn't an entry found, discard the packet.
- Tunnel programme takes the UDP payload, creates an IPv4 header and puts it on top of the UDP payload. Writes the result to the tunnel interface.
  - IPv4 header details:
    - saddr:
      - If EndpointPort is not defined, IPv4 addr generated from the IPv4 saddr and UDP sport of the packet delivered to tunnel programme.
      - Else, IPv4 saddr on the packet delivered to tunnel programme.
    - daddr: First found IPv4 address assigned to the tunnel interface.
    - Protocol: TCP.

## Data TX Path

- Outgoing IPv4 packet on tunnel interface (tun) is delivered to tunnel programme.
- Discard the packet if it's not a TCP packet or if the IP header length is more than 20 bytes.
- If EndpointPort is not defined, look for an entry on the "connection_store" structure by using the IPv4 daddr on this packet. If there isn't an entry found, discard the packet.
- Else, initiate authentication when needed, TCP connection to IPv4 daddr on the packet delivered to tunnel programme and EndpointPort with ListenPort as TCP sport. Deliver credentials. Discard the packet if authentication fails.
- Tunnel programme removes the IPv4 header from the IPv4 packet. Sends it as an outgoing UDP packet on the bound interface.
  - IPv4 header details:
    - saddr: Decided by kernel by consulting the relevant routing table.
    - daddr:
      - If EndpointPort is not defined, IPv4 addr on the "connection_store" structure found from IPv4 daddr on the packet delivered to tunnel programme.
      - Else, IPv4 daddr on the packet delivered to tunnel programme.
  - UDP header details:
    - sport: Decided by kernel, which is the port defined on the ListenPort option.
    - dport:
      - If EndpointPort is not defined, UDP port on the "connection_store" structure found from IPv4 daddr on the packet delivered to tunnel programme.
      - Else, port defined on the EndpointPort option.
