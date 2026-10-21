"""Captura de trafico a .pcap (RS4). Uso en contenedor con CAP_NET_RAW."""
import argparse

from scapy.all import TCP, PcapWriter, sniff

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", type=int, nargs="+", default=[8443, 8080])
    ap.add_argument("--out", default="evidence/captura.pcap")
    ap.add_argument("--iface", default="eth0")
    a = ap.parse_args()
    ports = set(a.ports)
    w = PcapWriter(a.out, append=False, sync=True)
    print(f"[CAPTURA] iface={a.iface} puertos={sorted(ports)} -> {a.out}", flush=True)
    sniff(iface=a.iface, store=False, prn=w.write,
          lfilter=lambda p: p.haslayer(TCP) and
                            (p[TCP].sport in ports or p[TCP].dport in ports))

if __name__ == "__main__":
    main()