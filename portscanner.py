"""
PortPeek — a simple multithreaded TCP port scanner.

Usage:
    python portscanner.py --target 127.0.0.1 --ports 1-1000 --i-have-authorization
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# A small lookup table so we can show a friendly service name next to
# open ports, instead of just a bare number.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-alt",
}


def parse_ports(port_arg: str) -> list[int]:
    """
    Turn a CLI argument like "1-1024" or "22,80,443" into a list of ints.
    """
    ports = set()
    for chunk in port_arg.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(chunk))
    return sorted(ports)


def scan_port(target: str, port: int, timeout: float) -> tuple[int, bool, str]:
    """
    Try to open a TCP connection to (target, port).
    Returns (port, is_open, banner_or_service_name).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result != 0:
                return port, False, ""

            # Port is open — try to grab a banner (some services announce
            # themselves right after connecting, e.g. SSH, FTP).
            banner = ""
            try:
                sock.settimeout(1.0)
                data = sock.recv(128)
                banner = data.decode(errors="ignore").strip()
            except (socket.timeout, OSError):
                pass

            label = banner if banner else COMMON_PORTS.get(port, "unknown")
            return port, True, label

    except (socket.timeout, OSError):
        return port, False, ""


def scan_target(target: str, ports: list[int], timeout: float, max_workers: int):
    """
    Scan every port in `ports` against `target`, using a thread pool so we
    don't wait for each connection attempt one after another.
    """
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, target, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port, is_open, label = future.result()
            if is_open:
                open_ports.append((port, label))

    return sorted(open_ports)


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address, or return it unchanged if it
    already is one."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: could not resolve host '{target}'", file=sys.stderr)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portpeek",
        description="PortPeek — a simple multithreaded TCP port scanner "
                     "for authorized security testing.",
    )
    parser.add_argument("--target", required=True,
                         help="Target IP address or hostname")
    parser.add_argument("--ports", default="1-1024",
                         help="Ports to scan: a range (1-1024) or a list "
                              "(22,80,443). Default: 1-1024")
    parser.add_argument("--timeout", type=float, default=0.5,
                         help="Connection timeout in seconds (default: 0.5)")
    parser.add_argument("--threads", type=int, default=100,
                         help="Number of concurrent threads (default: 100)")
    parser.add_argument("--i-have-authorization", action="store_true",
                         help="Confirm you are authorized to scan this target")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.i_have_authorization:
        print(
            "Refusing to scan: pass --i-have-authorization to confirm you "
            "own this target or have explicit written permission to test it.\n"
            "Unauthorized port scanning may be illegal in your jurisdiction.",
            file=sys.stderr,
        )
        return 2

    ip = resolve_target(args.target)
    ports = parse_ports(args.ports)

    print(f"PortPeek — scanning {args.target} ({ip})")
    print(f"Ports: {len(ports)} | Threads: {args.threads} | "
          f"Timeout: {args.timeout}s")
    print(f"Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    start = datetime.now()
    open_ports = scan_target(ip, ports, args.timeout, args.threads)
    elapsed = (datetime.now() - start).total_seconds()

    if not open_ports:
        print("No open ports found.")
    else:
        print(f"{'PORT':<8}{'STATE':<8}{'SERVICE / BANNER'}")
        for port, label in open_ports:
            print(f"{port:<8}{'open':<8}{label}")

    print(f"\nScan completed in {elapsed:.2f} seconds. "
          f"{len(open_ports)} open port(s) found.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
