import pcapy
import dpkt
import socket
from collections import defaultdict
from datetime import datetime, timedelta


log = defaultdict(list)
logged_ips = set()


cap = pcapy.open_live("lo0", 65536, 1, 100)


def process(header, packet):
    try:
        ip = dpkt.ip.IP(packet[4:]) 
        tcp = ip.data
        if isinstance(tcp, dpkt.tcp.TCP):
            if tcp.flags & dpkt.tcp.TH_SYN:
                src_ip = socket.inet_ntoa(ip.src)
                dport = tcp.dport

                now = datetime.now()
                log[src_ip].append((dport, now))

                start = now - timedelta(minutes=5)
                log[src_ip] = [(port, t) for port, t in log[src_ip] if t >= start]

                ports = sorted(set(port for port, _ in log[src_ip]))

                for i in range(len(ports) - 14):
                    if ports[i + 14] - ports[i] == 14:
                        if src_ip not in logged_ips:
                            with open("detector.txt", "a") as f:
                                f.write(f"Scanner detected. The scanner originated from host {src_ip}.\n")
                            logged_ips.add(src_ip)
                        break
    except KeyboardInterrupt:
        raise
    except Exception:
        pass

try:
    while True:
        cap.dispatch(1, process)     
except KeyboardInterrupt:
    exit