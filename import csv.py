import csv
import os
import time
import queue
from collections import Counter, deque
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from scapy.all import AsyncSniffer, IP, TCP, UDP, ARP, get_if_list


LOG_FILE = "packets_log.csv"
STATS_INTERVAL = 1.0
MAX_ROWS = 1000
TOP_N = 10


# ----------------- 서비스 분류 규칙 -----------------
# 필요하면 여기에 계속 추가하면 됨.
TCP_PORT_SERVICE = {
    443: "HTTPS",
    80: "HTTP",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3389: "RDP",
}

UDP_PORT_SERVICE = {
    53: "DNS",
    123: "NTP",
    67: "DHCP",
    68: "DHCP",
    161: "SNMP",
    162: "SNMP",
}


def is_steam_port(port: int | None) -> bool:
    if port is None:
        return False
    # 흔히 보는 Steam/게임 포트 대역(대략)
    return 27000 <= port <= 27100


def classify_service(proto: str, sport, dport) -> str:
    """
    proto: "TCP", "UDP", "ARP", "IP(x)", "OTHER"
    sport/dport: int or None
    """
    if proto == "ARP":
        return "ARP"

    if proto == "TCP":
        if is_steam_port(sport) or is_steam_port(dport):
            return "Steam/Game"
        if dport in TCP_PORT_SERVICE:
            return TCP_PORT_SERVICE[dport]
        if sport in TCP_PORT_SERVICE:
            return TCP_PORT_SERVICE[sport]
        return "TCP-Other"

    if proto == "UDP":
        if dport in UDP_PORT_SERVICE:
            return UDP_PORT_SERVICE[dport]
        if sport in UDP_PORT_SERVICE:
            return UDP_PORT_SERVICE[sport]
        if is_steam_port(sport) or is_steam_port(dport):
            return "Steam/Game"
        return "UDP-Other"

    # IP(1)=ICMP 같은 케이스도 서비스로 묶어주기
    if proto.startswith("IP("):
        ipn = proto[3:-1]
        if ipn == "1":
            return "ICMP"
        return f"IP-{ipn}"

    return "OTHER"


class PacketAnalyzerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Shinseungyeop Packet GUI")
        self.geometry("1200x750")

        self.sniffer = None
        self.queue = queue.Queue()
        self.capturing = False

        # 카운터들
        self.proto_counter = Counter()
        self.service_counter = Counter()
        self.dst_counter = Counter()

        # pps 계산용
        self.recent_times = deque()

        self._init_csv(LOG_FILE)
        self._build_controls()
        self._build_tabs()
        self._build_statusbar()

        self.after(100, self._drain_queue)
        self.after(int(STATS_INTERVAL * 1000), self._update_stats_loop)

    # ---------------- UI ----------------
    def _build_controls(self):
        top = ttk.Frame(self, padding=(10, 8))
        top.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(top, text="Interface:").pack(side=tk.LEFT)
        self.if_var = tk.StringVar()
        self.if_combo = ttk.Combobox(top, textvariable=self.if_var, width=55, state="readonly")
        ifaces = list(get_if_list())
        self.if_combo["values"] = ["<Default>"] + ifaces
        self.if_combo.current(0)
        self.if_combo.pack(side=tk.LEFT, padx=6)

        ttk.Label(top, text="BPF Filter:").pack(side=tk.LEFT, padx=(10, 0))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(top, textvariable=self.filter_var, width=35)
        self.filter_entry.insert(0, "")
        self.filter_entry.pack(side=tk.LEFT, padx=6)

        self.start_btn = ttk.Button(top, text="Start", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=(12, 6))

        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # -------- Live Packets 탭 --------
        self.live_tab = ttk.Frame(nb)
        nb.add(self.live_tab, text="Live Packets")

        cols = ("time", "proto", "service", "src", "sport", "dst", "dport", "length")
        self.tree = ttk.Treeview(self.live_tab, columns=cols, show="headings", height=24)

        headings = {
            "time": "Time",
            "proto": "Proto",
            "service": "Service",
            "src": "Source",
            "sport": "SPort",
            "dst": "Destination",
            "dport": "DPort",
            "length": "Len",
        }
        widths = {"time":185, "proto":70, "service":120, "src":170, "sport":70, "dst":170, "dport":70, "length":70}
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor=tk.W)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll = ttk.Scrollbar(self.live_tab, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)

        # -------- Stats 탭 --------
        self.stats_tab = ttk.Frame(nb)
        nb.add(self.stats_tab, text="Stats")

        upper = ttk.Frame(self.stats_tab)
        upper.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # 왼쪽: 프로토콜/서비스 요약 + TOP 리스트
        left = ttk.Frame(upper)
        left.pack(side=tk.LEFT, fill=tk.Y)

        # 프로토콜 라벨
        self.tcp_var = tk.StringVar(value="TCP: 0")
        self.udp_var = tk.StringVar(value="UDP: 0")
        self.arp_var = tk.StringVar(value="ARP: 0")
        self.other_var = tk.StringVar(value="OTHER: 0")

        proto_box = ttk.LabelFrame(left, text="Protocol Counts", padding=8)
        proto_box.pack(fill=tk.X, pady=(0, 8))
        for var in (self.tcp_var, self.udp_var, self.arp_var, self.other_var):
            ttk.Label(proto_box, textvariable=var).pack(anchor=tk.W)

        # TOP 목적지 IP
        dst_box = ttk.LabelFrame(left, text=f"Top Destinations (dst IP) - Top {TOP_N}", padding=6)
        dst_box.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        self.dst_tree = ttk.Treeview(dst_box, columns=("rank", "dst", "count"), show="headings", height=10)
        self.dst_tree.heading("rank", text="#")
        self.dst_tree.heading("dst", text="Destination IP")
        self.dst_tree.heading("count", text="Packets")
        self.dst_tree.column("rank", width=40, anchor=tk.W)
        self.dst_tree.column("dst", width=220, anchor=tk.W)
        self.dst_tree.column("count", width=80, anchor=tk.W)
        self.dst_tree.pack(fill=tk.BOTH, expand=True)

        # TOP 서비스
        svc_box = ttk.LabelFrame(left, text=f"Top Services - Top {TOP_N}", padding=6)
        svc_box.pack(fill=tk.BOTH, expand=True)

        self.svc_tree = ttk.Treeview(svc_box, columns=("rank", "svc", "count"), show="headings", height=10)
        self.svc_tree.heading("rank", text="#")
        self.svc_tree.heading("svc", text="Service")
        self.svc_tree.heading("count", text="Packets")
        self.svc_tree.column("rank", width=40, anchor=tk.W)
        self.svc_tree.column("svc", width=220, anchor=tk.W)
        self.svc_tree.column("count", width=80, anchor=tk.W)
        self.svc_tree.pack(fill=tk.BOTH, expand=True)

        # 오른쪽: 그래프
        right = ttk.Frame(upper)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0))

        self.fig = Figure(figsize=(7, 4))
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("Protocol Distribution")
        self.ax.set_xlabel("Protocol")
        self.ax.set_ylabel("Count")
        self.canvas = FigureCanvasTkAgg(self.fig, master=right)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self._draw_proto_chart()

    def _build_statusbar(self):
        self.status_var = tk.StringVar(value="Ready")
        bar = ttk.Frame(self, padding=(10, 4))
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(bar, textvariable=self.status_var).pack(side=tk.LEFT)

    # ---------------- Capture control ----------------
    def start_capture(self):
        if self.capturing:
            return

        iface = self.if_var.get()
        if iface == "<Default>":
            iface = None

        bpf = self.filter_var.get().strip() or None

        try:
            self.sniffer = AsyncSniffer(
                iface=iface,
                filter=bpf,
                prn=self._on_packet,
                store=False
            )
            self.sniffer.start()
        except Exception as e:
            messagebox.showerror("Sniffer Error", str(e))
            return

        self.capturing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"Capturing... iface={iface or '<Default>'}  filter={bpf or '-'}")

    def stop_capture(self):
        if not self.capturing:
            return
        try:
            if self.sniffer:
                self.sniffer.stop()
        except Exception as e:
            messagebox.showwarning("Sniffer", f"Stop warning: {e}")
        finally:
            self.sniffer = None
            self.capturing = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_var.set("Stopped")

    # ---------------- Packet handling ----------------
    def _on_packet(self, pkt):
        info = self._extract_packet_info(pkt)
        # 서비스 분류 결과까지 포함해서 큐로 전달
        info["service"] = classify_service(info["proto"], info["sport"], info["dport"])
        self.queue.put(info)

    def _extract_packet_info(self, pkt):
        info = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "src": None,
            "dst": None,
            "proto": None,
            "sport": None,
            "dport": None,
            "length": len(pkt)
        }

        if IP in pkt:
            info["src"] = pkt[IP].src
            info["dst"] = pkt[IP].dst
            if TCP in pkt:
                info["proto"] = "TCP"
                info["sport"] = int(pkt[TCP].sport)
                info["dport"] = int(pkt[TCP].dport)
            elif UDP in pkt:
                info["proto"] = "UDP"
                info["sport"] = int(pkt[UDP].sport)
                info["dport"] = int(pkt[UDP].dport)
            else:
                info["proto"] = f"IP({pkt[IP].proto})"
        elif ARP in pkt:
            info["proto"] = "ARP"
            info["src"] = pkt[ARP].psrc
            info["dst"] = pkt[ARP].pdst
        else:
            info["proto"] = "OTHER"

        return info

    def _drain_queue(self):
        drained = 0
        while True:
            try:
                info = self.queue.get_nowait()
            except queue.Empty:
                break

            drained += 1
            self._append_row(info)
            self._update_counters(info)
            self._append_csv(info)

            now = time.time()
            self.recent_times.append(now)
            cutoff = now - STATS_INTERVAL
            while self.recent_times and self.recent_times[0] < cutoff:
                self.recent_times.popleft()

        if drained:
            pps = len(self.recent_times) / STATS_INTERVAL
            self.status_var.set(f"Capturing... pps={pps:.1f}")

        self.after(100, self._drain_queue)

    # ---------------- Table / Stats / CSV ----------------
    def _append_row(self, info):
        values = (
            info["time"],
            info["proto"],
            info.get("service"),
            info["src"],
            info["sport"],
            info["dst"],
            info["dport"],
            info["length"],
        )
        self.tree.insert("", tk.END, values=values)

        if len(self.tree.get_children()) > MAX_ROWS:
            first = self.tree.get_children()[0]
            self.tree.delete(first)

    def _update_counters(self, info):
        proto = info["proto"]
        service = info.get("service", "OTHER")
        dst = info["dst"] or "?"

        self.proto_counter[proto] += 1
        self.service_counter[service] += 1
        self.dst_counter[dst] += 1

    def _update_stats_loop(self):
        tcp = self.proto_counter.get("TCP", 0)
        udp = self.proto_counter.get("UDP", 0)
        arp = self.proto_counter.get("ARP", 0)
        other = sum(v for k, v in self.proto_counter.items() if k not in ("TCP", "UDP", "ARP"))

        self.tcp_var.set(f"TCP: {tcp}")
        self.udp_var.set(f"UDP: {udp}")
        self.arp_var.set(f"ARP: {arp}")
        self.other_var.set(f"OTHER: {other}")

        self._draw_proto_chart()
        self._refresh_top_tables()

        self.after(int(STATS_INTERVAL * 1000), self._update_stats_loop)

    def _draw_proto_chart(self):
        self.ax.clear()
        labels = []
        counts = []

        tcp = self.proto_counter.get("TCP", 0)
        udp = self.proto_counter.get("UDP", 0)
        arp = self.proto_counter.get("ARP", 0)
        other = sum(v for k, v in self.proto_counter.items() if k not in ("TCP", "UDP", "ARP"))

        for k, v in [("TCP", tcp), ("UDP", udp), ("ARP", arp), ("OTHER", other)]:
            labels.append(k)
            counts.append(v)

        self.ax.bar(labels, counts)
        self.ax.set_title("Protocol Distribution")
        self.ax.set_xlabel("Protocol")
        self.ax.set_ylabel("Count")
        self.fig.tight_layout()
        self.canvas.draw_idle()

    def _refresh_top_tables(self):
        # dst top
        for item in self.dst_tree.get_children():
            self.dst_tree.delete(item)
        for idx, (dst, cnt) in enumerate(self.dst_counter.most_common(TOP_N), start=1):
            self.dst_tree.insert("", tk.END, values=(idx, dst, cnt))

        # service top
        for item in self.svc_tree.get_children():
            self.svc_tree.delete(item)
        for idx, (svc, cnt) in enumerate(self.service_counter.most_common(TOP_N), start=1):
            self.svc_tree.insert("", tk.END, values=(idx, svc, cnt))

    # ---------------- CSV ----------------
    def _init_csv(self, path):
        new_file = not os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["time", "src", "dst", "proto", "service", "sport", "dport", "length"])

    def _append_csv(self, info):
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                info["time"],
                info["src"],
                info["dst"],
                info["proto"],
                info.get("service"),
                info["sport"],
                info["dport"],
                info["length"],
            ])


if __name__ == "__main__":
    app = PacketAnalyzerGUI()
    app.mainloop()
