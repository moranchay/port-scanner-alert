import socket
import json
import argparse
import os
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

FIRST_PORT = 1
LAST_PORT = 65535
DEFAULT_PORT = 1024

def parse_args():
    parser = argparse.ArgumentParser(description="Port scanner (baseline compare).")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--all", action="store_true", help="Scan all ports (1-65535)")
    group.add_argument("--range", type=str, help="Port range like 1-1024 or single port 80")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP (default 127.0.0.1)")
    parser.add_argument("--threads", type=int, default=200, help="Threads ammount (default 200)")
    parser.add_argument("--update-baseline", action="store_true", help="Overwrite baseline with current scan (use carefully)")
    parser.add_argument("--baseline-file", default="baseline.json", help="Path to baseline file (default: baseline.json)")
    parser.add_argument("--keep-history", action="store_true", help="when updating baseline also have a timed history file")
    return parser.parse_args()

def range_from_args(args):
    if args.all:
        return FIRST_PORT, LAST_PORT
    if args.range:
        raw = args.range
        if "-" in raw:
            a,b = raw.split("-", 1)
            start, end = int(a), int(b)
        else:
            start = end = int(raw)
        if not (FIRST_PORT <= start <= LAST_PORT and FIRST_PORT <= end <= LAST_PORT and start <= end):
            raise ValueError("Invalid port range")
        return start,end
    return FIRST_PORT, DEFAULT_PORT


# common TCP ports and their services
PORT_SERVICES = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    123: "NTP",
    135: "RPC",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP (submission)",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
}

def map_ports_to_services(ports):
    result = []
    for port in ports:
        service = PORT_SERVICES.get(port, "Unknown")
        result.append(f"{port} ({service})")
    return result


# scans for open tcp port with 0.5 timeout. True if connected False if not.
def scan_port(ip, port, timeout=0.2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception:
        return False
    finally:
        sock.close()

 #scans a range of tcp ports and returns a list of open ports.
def scan_range(ip, start=1, end=1024, max_threads=200):
    open_ports = []

    def worker(port):
        if scan_port(ip, port):
            return port
        return None
    
    #use ThreadPoolExecutor to scan ports in parallel
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(worker, port): port for port in range(start, end + 1)}

        for future in as_completed(future_to_port):
            port = future.result()
            if port is not None:
                open_ports.append(port)
    return sorted(open_ports)

# saves a baseline of open ports to a file using JSON format.
def save_baseline(baseline, filename='baseline.json', keep_history=False):
    # ensure file directory exists
    dirname = os.path.dirname(os.path.abspath(filename))
    if not os.path.isdir(dirname):
        os.makedirs(dirname, exist_ok=True)

    # write main baseline file
    with open(filename, 'w') as f:
        json.dump(baseline, f, indent=2)

    # optionally save a timestamped copy for history
    if keep_history:
        ts = datetime.datetime.now().strftime("%Y%m%dT%H%M")
        base, ext = os.path.splitext(filename)
        hist_name = f"{base}_{ts}{ext or '.json'}"
        with open(hist_name, 'w') as hf:
            json.dump({
                "timestamp_utc": ts,
                "baseline": baseline,
            }, hf, indent=2)

# loads the baseline of open ports to JSON format. if no file return [].
def load_baseline(filename='baseline.json'):
    try:
        with open(filename) as f:
            return json.load(f)
    except FileNotFoundError:
        return []

if __name__ == '__main__':
    args = parse_args()
    try:
        start, end = range_from_args(args)
    except ValueError as e:
        print("Error ", e)
        raise SystemExit(1)
    
    target = args.target
    threads = args.threads
    baseline_file = args.baseline_file
    baseline_exists = os.path.exists(baseline_file)

    # load baseline (empty list if not found) 
    baseline = load_baseline(baseline_file)
    
    # perform the scan
    print(f"scanning {target} => ports {start}-{end} using {threads} threads")
    current = scan_range(target, start, end, threads)
    current = map_ports_to_services(current)
    #compare and show results
    new = sorted(set(current) -set(baseline))
    closed = sorted(set(baseline) -set(current))

    if new:
        print("ALERT: new open ports: ", new)
    else:
        print("No new ports. Looks good!")

    if closed:
        print("Ports closed since last run: ", closed)

    print("Current open ports: ", current)

    if not baseline_exists:
        print(f"No baseline found. creating baseline at '{baseline_file}'.")
        save_baseline(current, baseline_file, keep_history=args.keep_history)
    elif args.update_baseline:
        print(f"Updating baseline at '{baseline_file}' (keep_history={args.keep_history}).")
        save_baseline(current, baseline_file, keep_history=args.keep_history)
    else:
        print("Baseline not updated, to update baseline pass --update-baseline.")