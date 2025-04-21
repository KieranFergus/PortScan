import argparse
import socket
import time
import random

parser = argparse.ArgumentParser()
parser.add_argument("target")

args = parser.parse_args()
target = args.target
tcp_max = 65535

f = open("scannertoo.txt", "w")

start = time.perf_counter()

ports = list(range(0, tcp_max + 1))
random.shuffle(ports)

for port in ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((target, port))
        if result == 0:
            try:
                name = socket.getservbyport(port, 'tcp')
            except:
                name = "NA"
            f.write(f"{port} ({name}) was open\n")
        s.close()
    except KeyboardInterrupt:
        break

end = time.perf_counter()

runtime = end - start
tps = runtime / tcp_max
f.write(f"time elapsed = {runtime:.2f}s\n")
f.write(f"time per scan = {tps:.4f}s")

f.close()