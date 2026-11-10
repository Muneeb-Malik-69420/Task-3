# CodeAlpha_NetworkSniffer

A Python command-line network sniffer that uses Scapy to capture live traffic
from an interface you choose. It prints one line per packet and can record a
capture for later inspection.

## Project structure

```text
CodeAlpha_NetworkSniffer/
├── .gitignore
├── README.md
├── requirements.txt
└── sniffer.py
```

## Setup

Install Python 3.10 or newer. On Windows, install Npcap. If Npcap was configured
to restrict capture to administrators, open PowerShell with **Run as
administrator**. [Npcap download](https://npcap.com/#download) ·
[Scapy installation guide](https://scapy.readthedocs.io/en/stable/installation.html)

Open a terminal in the `CodeAlpha_NetworkSniffer` folder. On Windows, run:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe sniffer.py
```

On Linux or macOS, use the commands below. On Linux, install your distribution's
libpcap package for BPF filters. Live capture may require elevated permissions.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
sudo .venv/bin/python sniffer.py
```

## Usage

Pick the number beside your Wi-Fi, Ethernet, or loopback interface. Capture
continues until you press **Ctrl+C** or reach the requested packet count.

```powershell
.\.venv\Scripts\python.exe sniffer.py --help
.\.venv\Scripts\python.exe sniffer.py --count 10 --filter "tcp or udp" --save capture.pcap
```

| Option | What it does |
| --- | --- |
| `--count N` | Stop after capturing `N` matching packets. |
| `--filter BPF` | Capture only traffic matching a Berkeley Packet Filter expression such as `"udp port 53"`. |
| `--save FILE.pcap` | Stream full captured packets into a new PCAP file. The file is created when the first packet arrives. Use a new filename for each run. |

For a quick Windows check, run the sniffer with `--count 2 --filter "icmp"`,
choose the adapter you use to reach your router, and ping your router once from
a second terminal with `ping -n 1 YOUR_ROUTER_IP`. Replace `YOUR_ROUTER_IP` with
its IPv4 address. A successful ping produces a request and a reply.

## Sample output

This illustrative output uses example addresses and payloads.

```text
Timestamp (UTC) | Source IP -> Destination IP | Protocol | Source port -> Destination port | Payload preview
2026-11-09T06:45:12.032Z | 192.0.2.10 -> 198.51.100.20 | TCP | 52015 -> 443 | -
2026-11-09T06:45:12.104Z | 192.0.2.10 -> 198.51.100.20 | HTTP | 52016 -> 8080 | GET /status HTTP/1.1..Host: example.test....
2026-11-09T06:45:12.267Z | 192.0.2.10 -> 198.51.100.1 | DNS | 54421 -> 53 | .............example.test.....
2026-11-09T06:45:12.510Z | 192.0.2.10 -> 198.51.100.1 | ICMP | - -> - | ping
```

The preview shows up to 60 payload bytes. Bytes outside printable ASCII appear
as dots. A dash indicates an empty preview or an unavailable address or port.

## Limitations

- The sniffer sees only traffic delivered to the selected interface. Capture
  runs with promiscuous mode disabled.
- Protocol detection works on individual packets. DNS is labeled when Scapy
  decodes it. Plaintext HTTP/1.x requires a recognizable start line in one
  TCP packet. A start line split across TCP segments may appear as TCP.
- Encrypted payloads stay encrypted. HTTPS over TCP appears as TCP, and
  HTTP/3 over QUIC appears as UDP.

## Ethical use

Capture traffic only on devices and networks you own or have explicit
permission to monitor. Treat console previews and PCAP files as sensitive.
Capture files contain full captured packets, which can include passwords and
private data. Never commit capture files to Git.
