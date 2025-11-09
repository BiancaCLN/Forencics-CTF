# Challenge — `ntp_capture.pcap`

## Summary
The capture contained NTP traffic that — when inspected and the UDP payloads aligned — revealed a hidden CTF message. The PCAP included NTP packets on port 123; some packets were flagged as malformed (truncated payloads / unexpected lengths). Because NTP uses UDP (no stream reassembly by TCP), the hidden message was split across multiple datagrams and required extracting each UDP payload and concatenating them in time order to reconstruct the plaintext.

> **Files:** `ntp_capture.pcap`

---

## What is NTP?
NTP (Network Time Protocol) is a protocol used to synchronize clocks of computers over packet-switched, variable-latency networks.  
Key points:
- NTP keeps system clocks accurate by exchanging timestamped messages with NTP servers/peers.
- Standard transport: **UDP**, port **123**.
- Typical NTP packet fields include: LI (Leap Indicator), Version, Mode (client/server/broadcast), Stratum, Poll, Precision, Root Delay, Root Dispersion, Reference ID, and several timestamps (Reference, Originate, Receive, Transmit).
- NTP packets are small (typically 48 bytes for a basic pkt), so UDP’s low overhead is a good fit.

---

## What network traffic/structure should we expect?
When investigating an NTP PCAP you typically expect:
- UDP packets to/from port **123** (either src or dst == 123).
- Small fixed-length messages (NTP header + optional extensions).
- Typical conversation patterns:
  - Client → Server: NTP request (mode 3)
  - Server → Client: NTP reply (mode 4) with timestamps
- Broadcast/multicast messages are possible (mode 5/6).
- Timestamps let you order and correlate packets for timeline analysis.

---

## Why UDP for NTP?
- **Low overhead / latency:** UDP has minimal framing and no connection handshake; time sync requires fast, small exchanges.
- **No retransmission semantics:** NTP can tolerate occasional loss and uses statistical filtering — retransmission at transport level would add unwanted jitter and delay.
- **Small, frequent packets:** UDP is efficient for short periodic messages like NTP.

Tradeoffs: UDP provides no reliability guarantees or ordering, so the client/server logic and filtering in NTP handle offsets, jitter and packet loss.

---

## What does “malformed” mean here?
Wireshark/tshark will mark packets "Malformed" when the captured bytes don't match the expected protocol structure. Common causes:
- **Truncated frames** — capture cut off mid-packet (frame length < protocol minimum).
- **Incorrect length field** — a captured datagram length inconsistent with the IP/UDP lengths.
- **Custom/crafted payloads** — someone intentionally placed non-NTP data into an NTP-sized payload (CTF trick).
- **Corrupted capture** — capture file was partially corrupted or concatenated badly.

In this challenge the “malformed” indication likely meant either:
- the NTP header was valid but the payload contained arbitrary ASCII/hex data (so Wireshark couldn’t parse as normal extensions), or  
- the pcap had many short/truncated UDP packets containing fragments of a hidden message.

---

