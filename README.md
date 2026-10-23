# 🔍 Network Packet Analyzer

A dark-themed, GUI-based network packet sniffer and analyzer built with Python, Tkinter, and Scapy. Designed as a college cybersecurity project for capturing and inspecting live network traffic in real time.

> ⚠️ **Legal Notice:** Only capture traffic on networks you own or are explicitly authorized to monitor. Unauthorized packet sniffing is illegal in most jurisdictions.

---

## ✨ Features

- **Live Packet Capture** — Sniff traffic on any network interface with optional BPF filters
- **Protocol Color Coding** — Visual distinction for TCP, UDP, ICMP, ARP, IPv6, and more
- **Real-time Statistics** — Live counters for total packets, traffic volume, packets/sec, TCP, UDP, and others
- **Payload Inspection** — View packet payloads in both readable text and hex dump format
- **Analysis Tab** — Top talkers, top conversations, top destination ports, and protocol/service bar charts
- **BPF Filter Support** — Custom or preset filters (`tcp`, `udp`, `port 80 or port 443`, `not port 22`, etc.)
- **Export Options** — Save captures as `.pcap` (Wireshark-compatible) or export to `.csv`
- **Dark Theme UI** — Clean, modern dark interface built entirely with Tkinter

---

## 📸 Screenshots

> *(Add screenshots of your app here)*

---

## 🗂️ Project Structure

```
.
├── server.py           # Main GUI application (SnifferApp)
├── packet_analyzer.py  # Packet parsing and analysis logic (PacketAnalyzer, SERVICE_PORTS)
└── README.md
```

---

## ⚙️ Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)

Install dependencies:

```bash
pip install scapy
```

### Windows (Extra Step)
Install **[Npcap](https://npcap.com/)** with *"WinPcap API-compatible mode"* checked during installation.

---

## 🚀 Usage

### Linux / macOS
Packet capture requires root privileges:

```bash
sudo python server.py
```

### Windows
Run **Command Prompt as Administrator**, then:

```cmd
python server.py
```

---

## 🖥️ How It Works

1. **Select a network interface** from the dropdown (active interfaces are listed first with their IP)
2. **Optionally set a BPF filter** — type one manually or pick a preset
3. Click **Start** to begin live capture
4. Click any row in the packet table to inspect **packet details and payload**
5. Switch to the **Analysis** tab for protocol charts and traffic statistics
6. Use **Save PCAP** or **Export CSV** to save captured data

---

## 🔎 Supported Protocols

| Protocol | Color     |
|----------|-----------|
| TCP      | Blue      |
| UDP      | Green     |
| ICMP     | Orange    |
| ARP      | Purple    |
| IPv6     | Teal      |
| IP       | Light Blue|
| Other    | Gray      |

---

## 📤 Export Formats

| Format | Description                             |
|--------|-----------------------------------------|
| `.pcap`| Compatible with Wireshark and tcpdump   |
| `.csv` | Timestamp, protocol, IPs, ports, length |

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes only**. The author is not responsible for any misuse. Always obtain proper authorization before capturing network traffic.

---

## 👨‍💻 Author

> *(Add your name, college, and year here)*

---

## 📄 License

This project is for academic/educational use. See [LICENSE](LICENSE) for details.
