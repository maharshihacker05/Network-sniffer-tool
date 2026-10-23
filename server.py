#!/usr/bin/env python3
"""
Network Packet Analyzer (GUI)
College project. Capture and analyze traffic only on networks you are authorized to monitor.

Requirements:  pip install scapy
Windows:       install Npcap (WinPcap API-compatible mode) and run as Administrator.
"""

import csv
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog

try:
    from scapy.all import conf, get_if_list, sniff, wrpcap
    SCAPY_OK = True
    SCAPY_ERR = ""
except Exception as exc:
    SCAPY_OK = False
    SCAPY_ERR = str(exc)

from packet_analyzer import PacketAnalyzer, SERVICE_PORTS

# ---------- Theme ----------
BG = "#0f1117"
PANEL = "#171a23"
CARD = "#1c2030"
BORDER = "#2a3045"
TEXT = "#e6e8ef"
MUTED = "#8b93a7"
ACCENT = "#5b8def"
DANGER = "#d05467"
FONT = "Segoe UI"
MONO = "Consolas"

PROTO_COLORS = {
    "TCP": "#7aa2f7", "UDP": "#9ece6a", "ICMP": "#e0af68",
    "ARP": "#bb9af7", "IPv6": "#73daca", "IP": "#7dcfff", "OTHER": "#8b93a7",
}

MAX_ROWS = 2000
PRESET_FILTERS = ["", "tcp", "udp", "icmp", "arp", "port 53", "port 80 or port 443", "not port 22"]


# ---------- Helpers ----------
def list_interfaces():
    """Return [(label, scapy_name)] with active adapters first."""
    entries = []
    try:
        for iface in conf.ifaces.values():
            name = iface.name
            desc = getattr(iface, "description", "") or name
            ip = getattr(iface, "ip", "") or ""
            label = f"{desc}  [{ip}]" if ip else desc
            active = ip not in ("", "0.0.0.0", "127.0.0.1")
            entries.append((active, label, name))
    except Exception:
        try:
            entries = [(False, n, n) for n in get_if_list()]
        except Exception:
            entries = []
    entries.sort(key=lambda e: not e[0])
    return [(label, name) for _, label, name in entries]


def printable_text(data: bytes, limit: int = 2000) -> str:
    text = data[:limit].decode("utf-8", errors="replace")
    return "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "." for ch in text)


def hexdump(data: bytes, width: int = 16, limit: int = 1024) -> str:
    if not data:
        return "(no payload)"
    chunk = data[:limit]
    lines = []
    for off in range(0, len(chunk), width):
        row = chunk[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in row).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{off:04x}  {hex_part}  {ascii_part}")
    if len(data) > limit:
        lines.append(f"... {len(data) - limit} more bytes")
    return "\n".join(lines)


def human_bytes(n: float) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


class SnifferApp:
    def __init__(self, root):
        self.root = root
        root.title("Network Packet Analyzer")
        root.geometry("1180x760")
        root.minsize(1000, 650)
        root.configure(bg=BG)

        self.analyzer = PacketAnalyzer()
        self.ui_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.iid_records = {}
        self.iface_map = {}
        self._last_count = 0
        self._last_time = time.time()

        self._setup_styles()
        self._build_ui()
        self._load_interfaces()

        self.root.after(60, self._poll_queue)
        self.root.after(500, self._refresh_stats)
        self.root.after(1000, self._refresh_analysis)

    def run(self):
        self.root.mainloop()

    # ---------- Styling ----------
    def _setup_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=TEXT, font=(FONT, 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Card.TFrame", background=CARD)
        style.configure("CardTitle.TLabel", background=CARD, foreground=MUTED, font=(FONT, 8, "bold"))
        style.configure("CardValue.TLabel", background=CARD, foreground=TEXT, font=(FONT, 18, "bold"))

        style.configure("TButton", background=CARD, foreground=TEXT, padding=(12, 6), borderwidth=0)
        style.map("TButton",
                  background=[("active", BORDER), ("disabled", PANEL)],
                  foreground=[("disabled", MUTED)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#4a7ad8"), ("disabled", PANEL)])
        style.configure("Danger.TButton", background=DANGER, foreground="#ffffff")
        style.map("Danger.TButton", background=[("active", "#b8465a"), ("disabled", PANEL)])

        style.configure("TEntry", fieldbackground=CARD, foreground=TEXT, insertcolor=TEXT,
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER)
        style.configure("TCombobox", fieldbackground=CARD, foreground=TEXT, background=CARD,
                        arrowcolor=TEXT, bordercolor=BORDER)
        style.map("TCombobox", fieldbackground=[("readonly", CARD)], foreground=[("readonly", TEXT)])
        self.root.option_add("*TCombobox*Listbox.background", CARD)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)

        style.configure("TCheckbutton", background=BG, foreground=MUTED)
        style.map("TCheckbutton", background=[("active", BG)])

        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                        rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background=PANEL, foreground=MUTED,
                        relief="flat", font=(FONT, 9, "bold"), padding=6)
        style.map("Treeview", background=[("selected", "#2d3a5c")], foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading", background=[("active", BORDER)])

        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED, padding=(16, 8))
        style.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", TEXT)])

        style.configure("Vertical.TScrollbar", background=CARD, troughcolor=BG,
                        bordercolor=BG, arrowcolor=MUTED)
        style.configure("TLabelframe", background=BG, bordercolor=BORDER)
        style.configure("TLabelframe.Label", background=BG, foreground=MUTED, font=(FONT, 9, "bold"))

    def _make_text(self, parent, height, width):
        t = tk.Text(parent, height=height, width=width, bg=CARD, fg=TEXT,
                    insertbackground=TEXT, relief="flat", borderwidth=0,
                    highlightthickness=0, font=(MONO, 10), padx=8, pady=6, wrap="none")
        t.pack(fill="both", expand=True)
        t.config(state="disabled")
        return t

    @staticmethod
    def _set_text(widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.config(state="disabled")

    # ---------- Layout ----------
    def _build_ui(self):
        header = ttk.Frame(self.root, padding=(18, 14, 18, 6))
        header.pack(fill="x")
        ttk.Label(header, text="Network Packet Analyzer", font=(FONT, 16, "bold")).pack(anchor="w")
        ttk.Label(header, text="Live capture, protocol analysis and payload inspection",
                  style="Muted.TLabel").pack(anchor="w")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=(4, 0))
        capture_tab = ttk.Frame(self.notebook, padding=12)
        analysis_tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(capture_tab, text="  Live Capture  ")
        self.notebook.add(analysis_tab, text="  Analysis  ")
        self._build_capture_tab(capture_tab)
        self._build_analysis_tab(analysis_tab)

        self.status_var = tk.StringVar(value="Ready" if SCAPY_OK else f"Scapy error: {SCAPY_ERR}")
        ttk.Label(self.root, textvariable=self.status_var, style="Muted.TLabel",
                  padding=(18, 6)).pack(fill="x", side="bottom")

    def _build_capture_tab(self, parent):
        # Row 1: interface, filter
        row1 = ttk.Frame(parent)
        row1.pack(fill="x")
        ttk.Label(row1, text="Interface").pack(side="left")
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(row1, textvariable=self.iface_var, width=48, state="readonly")
        self.iface_combo.pack(side="left", padx=(8, 16))

        ttk.Label(row1, text="BPF filter").pack(side="left")
        self.filter_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.filter_var, width=22).pack(side="left", padx=(8, 6))
        preset = ttk.Combobox(row1, values=PRESET_FILTERS, width=18, state="readonly")
        preset.set("presets")
        preset.pack(side="left")
        preset.bind("<<ComboboxSelected>>", lambda e: self.filter_var.set(preset.get()))

        # Row 2: actions
        row2 = ttk.Frame(parent)
        row2.pack(fill="x", pady=(10, 0))
        self.start_btn = ttk.Button(row2, text="Start", style="Accent.TButton", command=self.start_capture)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(row2, text="Stop", style="Danger.TButton",
                                   command=self.stop_capture, state="disabled")
        self.stop_btn.pack(side="left", padx=8)

        ttk.Button(row2, text="Export CSV", command=self.export_csv).pack(side="right")
        ttk.Button(row2, text="Save PCAP", command=self.save_pcap).pack(side="right", padx=8)
        ttk.Button(row2, text="Clear", command=self.clear_all).pack(side="right", padx=8)
        self.autoscroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Auto-scroll", variable=self.autoscroll_var).pack(side="right", padx=8)

        # Stat cards
        cards = ttk.Frame(parent)
        cards.pack(fill="x", pady=12)
        self.cards = {}
        for key, title in [("packets", "Packets"), ("bytes", "Traffic"), ("pps", "Packets / sec"),
                           ("tcp", "TCP"), ("udp", "UDP"), ("other", "Other")]:
            card = ttk.Frame(cards, style="Card.TFrame", padding=(14, 10))
            card.pack(side="left", fill="x", expand=True, padx=(0, 8))
            ttk.Label(card, text=title.upper(), style="CardTitle.TLabel").pack(anchor="w")
            value = ttk.Label(card, text="0", style="CardValue.TLabel")
            value.pack(anchor="w")
            self.cards[key] = value

        # Packet table
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill="both", expand=True)
        cols = ("time", "proto", "service", "src", "dst", "len", "info")
        headers = ("Time", "Proto", "Service", "Source", "Destination", "Len", "Info")
        widths = (110, 70, 90, 180, 180, 60, 430)
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        for c, h, w in zip(cols, headers, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w", stretch=(c == "info"))
        vs = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        for proto, color in PROTO_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Details + payload
        details = ttk.Frame(parent)
        details.pack(fill="x", pady=(10, 0))
        left = ttk.LabelFrame(details, text="Packet details", padding=8)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right = ttk.LabelFrame(details, text="Payload", padding=8)
        right.pack(side="left", fill="both", expand=True)
        self.detail_text = self._make_text(left, height=9, width=50)
        self.payload_text = self._make_text(right, height=9, width=70)

    def _build_analysis_tab(self, parent):
        left = ttk.LabelFrame(parent, text="Protocol & service distribution", padding=10)
        left.pack(side="left", fill="y", padx=(0, 12))
        self.chart = tk.Canvas(left, width=380, height=520, bg=CARD, highlightthickness=0)
        self.chart.pack(fill="both", expand=True)

        right = ttk.Frame(parent)
        right.pack(side="left", fill="both", expand=True)
        self.talk_tree = self._make_table(right, "Top talkers (source IP)",
                                          ("IP", "Packets"), (300, 180))
        self.conv_tree = self._make_table(right, "Top conversations",
                                          ("Source -> Destination", "Packets"), (420, 120))
        self.port_tree = self._make_table(right, "Top destination ports",
                                          ("Protocol / Port", "Service", "Packets"), (200, 150, 120))

    def _make_table(self, parent, title, cols, widths):
        frame = ttk.LabelFrame(parent, text=title, padding=8)
        frame.pack(fill="both", expand=True, pady=(0, 10))
        ids = [str(i) for i in range(len(cols))]
        tree = ttk.Treeview(frame, columns=ids, show="headings", height=5)
        for iid, heading, width in zip(ids, cols, widths):
            tree.heading(iid, text=heading)
            tree.column(iid, width=width, anchor="w")
        tree.pack(fill="both", expand=True)
        return tree

    # ---------- Interfaces ----------
    def _load_interfaces(self):
        items = list_interfaces() if SCAPY_OK else []
        self.iface_map = {label: name for label, name in items}
        self.iface_combo["values"] = [label for label, _ in items]
        if items:
            self.iface_var.set(items[0][0])

    # ---------- Capture control ----------
    def start_capture(self):
        if not SCAPY_OK:
            messagebox.showerror("Scapy missing",
                                 f"Scapy import nahi ho raha:\n{SCAPY_ERR}\n\nRun: pip install scapy")
            return
        label = self.iface_var.get()
        iface = self.iface_map.get(label) or None
        bpf = self.filter_var.get().strip() or None

        self.stop_event.clear()
        self._set_running(True)
        msg = f"Capturing on {label or 'all interfaces'}"
        if bpf:
            msg += f"  |  filter: {bpf}"
        self.status_var.set(msg)
        threading.Thread(target=self._sniff_worker, args=(iface, bpf), daemon=True).start()

    def stop_capture(self):
        self.stop_event.set()
        self.stop_btn.config(state="disabled")
        self.status_var.set("Stopping...")

    def _sniff_worker(self, iface, bpf):
        try:
            while not self.stop_event.is_set():
                sniff(iface=iface, filter=bpf, store=False, timeout=1,
                      prn=lambda p: self.ui_queue.put(("packet", p)))
        except PermissionError:
            self.ui_queue.put(("error", "Permission denied. Command Prompt ko 'Run as administrator' karke chalayein."))
        except Exception as exc:
            self.ui_queue.put(("error", str(exc)))
        finally:
            self.ui_queue.put(("done", None))

    def _set_running(self, flag):
        self.running = flag
        self.start_btn.config(state="disabled" if flag else "normal")
        self.stop_btn.config(state="normal" if flag else "disabled")
        if not flag:
            self.status_var.set(f"Stopped. {self.analyzer.total_packets:,} packets captured.")

    # ---------- Processing (GUI thread only) ----------
    def _poll_queue(self):
        for _ in range(500):
            try:
                kind, data = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            if kind == "packet":
                self._handle_packet(data)
            elif kind == "error":
                self.status_var.set(f"Error: {data}")
                messagebox.showerror("Capture error", data)
            elif kind == "done":
                self._set_running(False)
        self.root.after(60, self._poll_queue)

    def _handle_packet(self, pkt):
        rec = self.analyzer.add(pkt)
        ts = datetime.fromtimestamp(rec.timestamp).strftime("%H:%M:%S.%f")[:-3]
        src = f"{rec.src}:{rec.sport}" if rec.sport is not None else rec.src
        dst = f"{rec.dst}:{rec.dport}" if rec.dport is not None else rec.dst

        iid = self.tree.insert("", "end", tags=(rec.proto,),
                               values=(ts, rec.proto, rec.app, src, dst, rec.length, rec.info))
        self.iid_records[iid] = rec

        children = self.tree.get_children()
        excess = len(children) - MAX_ROWS
        if excess > 0:
            for old in children[:excess]:
                self.tree.delete(old)
                self.iid_records.pop(old, None)

        if self.autoscroll_var.get():
            self.tree.yview_moveto(1.0)

    def _refresh_stats(self):
        a = self.analyzer
        now = time.time()
        elapsed = max(now - self._last_time, 1e-6)
        pps = (a.total_packets - self._last_count) / elapsed
        self._last_count, self._last_time = a.total_packets, now

        tcp = a.proto_counts["TCP"]
        udp = a.proto_counts["UDP"]
        self.cards["packets"].config(text=f"{a.total_packets:,}")
        self.cards["bytes"].config(text=human_bytes(a.total_bytes))
        self.cards["pps"].config(text=f"{pps:.1f}")
        self.cards["tcp"].config(text=f"{tcp:,}")
        self.cards["udp"].config(text=f"{udp:,}")
        self.cards["other"].config(text=f"{a.total_packets - tcp - udp:,}")
        self.root.after(500, self._refresh_stats)

    def _refresh_analysis(self):
        a = self.analyzer
        total = a.total_packets or 1
        self._fill(self.talk_tree, [(ip, f"{n:,}  ({n / total * 100:.1f}%)")
                                    for ip, n in a.top_talkers()])
        self._fill(self.conv_tree, [(f"{s}  ->  {d}", f"{n:,}")
                                    for (s, d), n in a.top_conversations()])
        self._fill(self.port_tree, [(f"{p}/{port}", SERVICE_PORTS.get(port, "-"), f"{n:,}")
                                    for (p, port), n in a.top_ports()])
        self._draw_chart()
        self.root.after(1000, self._refresh_analysis)

    @staticmethod
    def _fill(tree, rows):
        for iid in tree.get_children():
            tree.delete(iid)
        for row in rows:
            tree.insert("", "end", values=row)

    def _draw_chart(self):
        c = self.chart
        c.delete("all")
        w = max(c.winfo_width(), 380)
        a = self.analyzer
        total = a.total_packets or 1
        if a.total_packets == 0:
            c.create_text(w / 2, 200, text="No data yet. Start a capture.", fill=MUTED, font=(FONT, 10))
            return
        y = self._draw_bars(c, "PROTOCOLS", a.proto_counts.most_common(), total, w, 16,
                            lambda n: PROTO_COLORS.get(n, MUTED))
        self._draw_bars(c, "SERVICES", a.app_counts.most_common(8), total, w, y + 14,
                        lambda n: ACCENT)

    @staticmethod
    def _draw_bars(c, title, items, total, width, y, color_of):
        c.create_text(14, y, text=title, anchor="w", fill=MUTED, font=(FONT, 9, "bold"))
        y += 22
        if not items:
            return y
        top = items[0][1]
        bar_x = 14 + 100
        max_w = width - bar_x - 110
        for name, count in items:
            c.create_text(14, y + 10, text=name[:12], anchor="w", fill=TEXT, font=(FONT, 9))
            bw = max(3, int(max_w * count / top))
            c.create_rectangle(bar_x, y + 3, bar_x + bw, y + 17, fill=color_of(name), outline="")
            c.create_text(bar_x + bw + 8, y + 10, text=f"{count:,}  {count / total * 100:.0f}%",
                          anchor="w", fill=MUTED, font=(FONT, 9))
            y += 24
        return y

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        rec = self.iid_records.get(sel[0])
        if rec is None:
            return
        ports = f"{rec.sport} -> {rec.dport}" if rec.sport is not None else "-"
        rows = [
            ("Time", datetime.fromtimestamp(rec.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
            ("Protocol", rec.proto),
            ("Service", rec.app),
            ("Source", rec.src),
            ("Destination", rec.dst),
            ("Ports", ports),
            ("Length", f"{rec.length} bytes"),
            ("Payload", f"{len(rec.payload)} bytes"),
            ("Info", rec.info),
        ]
        self._set_text(self.detail_text, "\n".join(f"{k:<13}{v}" for k, v in rows))

        if rec.payload:
            content = f"TEXT\n{printable_text(rec.payload)}\n\nHEX DUMP\n{hexdump(rec.payload)}"
        else:
            content = "(no payload in this packet)"
        self._set_text(self.payload_text, content)

    # ---------- Actions ----------
    def clear_all(self):
        self.analyzer.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.iid_records.clear()
        self._set_text(self.detail_text, "")
        self._set_text(self.payload_text, "")
        self._last_count = 0
        self.status_var.set("Cleared")

    def save_pcap(self):
        if not self.analyzer.raw_packets:
            messagebox.showinfo("Nothing to save", "Pehle kuch packets capture karein.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap", filetypes=[("PCAP file", "*.pcap")],
            initialfile=f"capture_{datetime.now():%Y%m%d_%H%M%S}.pcap")
        if path:
            wrpcap(path, list(self.analyzer.raw_packets))
            self.status_var.set(f"Saved PCAP: {path}")

    def export_csv(self):
        if not self.analyzer.records:
            messagebox.showinfo("Nothing to export", "Pehle kuch packets capture karein.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV file", "*.csv")],
            initialfile=f"packets_{datetime.now():%Y%m%d_%H%M%S}.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["time", "protocol", "service", "src", "dst",
                             "sport", "dport", "length", "info"])
            for r in self.analyzer.records:
                writer.writerow([
                    datetime.fromtimestamp(r.timestamp).isoformat(timespec="milliseconds"),
                    r.proto, r.app, r.src, r.dst,
                    "" if r.sport is None else r.sport,
                    "" if r.dport is None else r.dport,
                    r.length, r.info,
                ])
        self.status_var.set(f"Saved CSV: {path}")


def main():
    root = tk.Tk()
    SnifferApp(root).run()


if __name__ == "__main__":
    main()
