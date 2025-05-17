import socket
import subprocess
import platform
import sys

def ping_host(host):
    """
    Ping the host to check if it is alive.
    Returns True if host responds, False otherwise.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        output = subprocess.check_output(['ping', param, '1', host],
                                         stderr=subprocess.STDOUT,
                                         universal_newlines=True)
        if "unreachable" in output.lower():
            return False
        return True
    except subprocess.CalledProcessError:
        return False

def scan_ports(host, ports):
    """
    Scan the given list of ports on the host.
    Returns a list of open ports.
    """
    open_ports = []
    print(f"Scanning {host} for open ports...")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # Timeout for fast scan
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except socket.error:
            pass
    return open_ports

def resolve_domain(domain):
    """
    Resolve a domain name to an IP address.
    """
    try:
        return socket.gethostbyname(domain)
    except socket.error:
        return None

def main():
    print("=== Simple Network Scanner ===")
    target = input("Enter IP address or domain to scan: ").strip()
    # Resolve domain if necessary
    ip = None
    if all(c.isdigit() or c == '.' for c in target):
        ip = target
    else:
        print(f"Resolving domain {target}...")
        ip = resolve_domain(target)
        if not ip:
            print(f"Could not resolve domain: {target}")
            sys.exit(1)
        else:
            print(f"Domain {target} resolved to {ip}")

    print(f"Pinging {ip} to check if host is alive...")
    if not ping_host(ip):
        print(f"Host {ip} is not responding to ping. It might be down or blocking ping.")
        # Proceed anyway or exit
        proceed = input("Do you want to continue scanning ports? (y/n): ").strip().lower()
        if proceed != 'y':
            sys.exit(0)
    else:
        print(f"Host {ip} is alive.")

    # Define a set of common ports to scan
    common_ports = [
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        25,   # SMTP
        53,   # DNS
        80,   # HTTP
        110,  # POP3
        139,  # NetBIOS
        143,  # IMAP
        443,  # HTTPS
        445,  # Microsoft DS
        3389  # Remote Desktop
    ]

    open_ports = scan_ports(ip, common_ports)

    if open_ports:
        print(f"Open ports on {ip}:")
        for port in open_ports:
            print(f"  Port {port} is open")
    else:
        print(f"No common open ports found on {ip}.")

if __name__ == "__main__":
    main()

