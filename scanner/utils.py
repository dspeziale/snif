# scanner/utils.py - Utility functions
import socket
import struct
import subprocess
import platform
import re
from datetime import datetime


def get_local_network_range():
    """Determina automaticamente il range di rete locale"""
    try:
        # Ottieni IP locale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Calcola network range (assume /24)
        ip_parts = local_ip.split('.')
        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

        return network

    except Exception:
        # Default fallback
        return "192.168.1.0/24"


def normalize_mac_address(mac):
    """Normalizza formato MAC address"""
    if not mac:
        return None

    # Rimuovi caratteri non hex (mantieni solo 0-9, A-F, a-f)
    clean_mac = re.sub(r'[^0-9A-Fa-f]', '', mac)

    if len(clean_mac) != 12:
        return None

    # Formato standard con :
    return ':'.join(clean_mac[i:i + 2] for i in range(0, 12, 2)).upper()


def parse_nmap_timing(timing_str):
    """Parse timing parameter per nmap"""
    if timing_str.upper().startswith('T'):
        return timing_str.upper()

    timing_map = {
        '0': 'T0', 'paranoid': 'T0',
        '1': 'T1', 'sneaky': 'T1',
        '2': 'T2', 'polite': 'T2',
        '3': 'T3', 'normal': 'T3',
        '4': 'T4', 'aggressive': 'T4',
        '5': 'T5', 'insane': 'T5'
    }

    return timing_map.get(timing_str.lower(), 'T4')


def get_os_info():
    """Ottiene informazioni OS del sistema corrente"""
    return {
        'system': platform.system(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor()
    }


def format_uptime(uptime_ticks):
    """Formatta uptime da ticks SNMP"""
    if not uptime_ticks:
        return "Unknown"

    try:
        # Converti ticks (centisecondi) in secondi
        seconds = int(uptime_ticks) // 100

        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60

        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"

    except (ValueError, TypeError):
        return "Unknown"


def validate_ip_range(ip_range):
    """Valida formato range IP"""
    try:
        import ipaddress
        network = ipaddress.IPv4Network(ip_range, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_mac_address(mac):
    """Valida formato MAC address"""
    if not mac:
        return False

    # Pattern per MAC address con diversi separatori
    patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$',  # xx:xx:xx:xx:xx:xx o xx-xx-xx-xx-xx-xx
        r'^[0-9A-Fa-f]{12}$',  # xxxxxxxxxxxx
        r'^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$'  # xxxx.xxxx.xxxx (Cisco)
    ]

    return any(re.match(pattern, mac) for pattern in patterns)


def validate_ip_address(ip):
    """Valida indirizzo IP"""
    if not ip:
        return False

    # Pattern per IPv4
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

    return bool(re.match(ipv4_pattern, ip))


def get_mac_from_arp(ip):
    """Tenta di ottenere MAC address da tabella ARP"""
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['arp', '-a', ip],
                                    capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # Parse output ARP Windows - cerca pattern MAC
                mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
                for line in result.stdout.split('\n'):
                    if ip in line:
                        mac_match = re.search(mac_pattern, line)
                        if mac_match:
                            return normalize_mac_address(mac_match.group())
        else:
            # Linux/Unix
            result = subprocess.run(['arp', '-n', ip],
                                    capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # Pattern più robusto per Linux
                mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
                for line in result.stdout.split('\n'):
                    if ip in line and 'no entry' not in line.lower():
                        mac_match = re.search(mac_pattern, line)
                        if mac_match:
                            return normalize_mac_address(mac_match.group())

    except Exception as e:
        print(f"Errore ARP lookup per {ip}: {e}")

    return None


def extract_cve_from_text(text):
    """Estrae CVE IDs da testo"""
    if not text:
        return []

    # Pattern corretto per CVE
    cve_pattern = r'CVE-\d{4}-\d{4,7}'

    matches = re.findall(cve_pattern, text, re.IGNORECASE)
    return list(set(matches))  # Rimuovi duplicati


def sanitize_filename(filename):
    """Rimuove caratteri non validi dai nomi file"""
    if not filename:
        return "unnamed"

    # Rimuovi caratteri non sicuri per filesystem
    clean_name = re.sub(r'[<>:"/\\|?*]', '_', filename)

    # Rimuovi spazi multipli e caratteri di controllo
    clean_name = re.sub(r'\s+', '_', clean_name)
    clean_name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', clean_name)

    # Limita lunghezza
    return clean_name[:200]


def parse_port_range(port_str):
    """Parse range di porte (es: '80,443,8000-8010')"""
    if not port_str:
        return []

    ports = []

    try:
        for part in port_str.split(','):
            part = part.strip()

            if '-' in part:
                # Range di porte
                start, end = part.split('-', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())

                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535:
                    ports.extend(range(start_port, end_port + 1))
            else:
                # Singola porta
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)

    except ValueError:
        return []

    return sorted(list(set(ports)))  # Rimuovi duplicati e ordina


def format_bytes(byte_count):
    """Formatta byte in unità leggibili"""
    if byte_count == 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(byte_count)

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f"{size:.1f} {units[unit_index]}"


def is_private_ip(ip_address):
    """Verifica se IP è privato/interno"""
    try:
        import ipaddress
        ip = ipaddress.IPv4Address(ip_address)
        return ip.is_private
    except:
        return False


def get_subnet_from_ip(ip_address, prefix_length=24):
    """Ottiene subnet da IP address"""
    try:
        import ipaddress
        network = ipaddress.IPv4Network(f"{ip_address}/{prefix_length}", strict=False)
        return str(network)
    except:
        return None


def ping_host(ip_address, timeout=3, count=1):
    """Ping host per testare connettività"""
    try:
        system = platform.system().lower()

        if system == 'windows':
            cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), ip_address]
        else:
            cmd = ['ping', '-c', str(count), '-W', str(timeout), ip_address]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        return result.returncode == 0

    except Exception:
        return False


def resolve_hostname(ip_address, timeout=5):
    """Risolve hostname da IP address"""
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def get_network_interfaces():
    """Ottiene informazioni interfacce di rete del sistema locale"""
    interfaces = []

    try:
        system = platform.system().lower()

        if system == 'windows':
            result = subprocess.run(['ipconfig', '/all'],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                interfaces = _parse_windows_interfaces(result.stdout)
        else:
            result = subprocess.run(['ifconfig', '-a'],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                interfaces = _parse_unix_interfaces(result.stdout)

    except Exception as e:
        print(f"Errore getting network interfaces: {e}")

    return interfaces


def _parse_windows_interfaces(output):
    """Parse interfacce Windows da ipconfig"""
    interfaces = []
    current = {}

    for line in output.split('\n'):
        line = line.strip()

        if 'adapter' in line.lower() and ':' in line:
            if current:
                interfaces.append(current)
            current = {'name': line.split('adapter')[-1].strip(':'),
                       'ips': [], 'mac': None}

        elif any(term in line for term in ['Physical Address', 'Fisico']):
            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', line)
            if mac_match:
                current['mac'] = normalize_mac_address(mac_match.group())

        elif any(term in line for term in ['IPv4', 'IP Address']):
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                ip = ip_match.group(1)
                if validate_ip_address(ip):
                    current['ips'].append(ip)

    if current:
        interfaces.append(current)

    return interfaces


def _parse_unix_interfaces(output):
    """Parse interfacce Unix/Linux da ifconfig"""
    interfaces = []
    current = {}

    for line in output.split('\n'):
        if not line.startswith(' ') and ':' in line:
            if current:
                interfaces.append(current)
            current = {'name': line.split(':')[0], 'ips': [], 'mac': None}

        elif 'ether' in line.lower() or 'hwaddr' in line.lower():
            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
            if mac_match:
                current['mac'] = normalize_mac_address(mac_match.group())

        elif 'inet ' in line and 'inet6' not in line:
            ip_match = re.search(r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                ip = ip_match.group(1)
                if validate_ip_address(ip):
                    current['ips'].append(ip)

    if current:
        interfaces.append(current)

    return interfaces


def calculate_network_info(ip, netmask):
    """Calcola informazioni di rete da IP e netmask"""
    try:
        import ipaddress

        # Converti netmask in prefix length se necessario
        if '.' in netmask:
            # Netmask in formato dotted (es: 255.255.255.0)
            netmask_obj = ipaddress.IPv4Address(netmask)
            prefix_length = sum(bin(int(x)).count('1') for x in str(netmask_obj).split('.'))
        else:
            # Prefix length (es: 24)
            prefix_length = int(netmask)

        network = ipaddress.IPv4Network(f"{ip}/{prefix_length}", strict=False)

        return {
            'network': str(network.network_address),
            'netmask': str(network.netmask),
            'broadcast': str(network.broadcast_address),
            'prefix_length': prefix_length,
            'num_hosts': network.num_addresses - 2,  # Escludi network e broadcast
            'first_host': str(list(network.hosts())[0]) if network.num_addresses > 2 else None,
            'last_host': str(list(network.hosts())[-1]) if network.num_addresses > 2 else None
        }

    except Exception as e:
        print(f"Errore calcolo network info: {e}")
        return None


def get_default_gateway():
    """Ottiene gateway predefinito del sistema"""
    try:
        system = platform.system().lower()

        if system == 'windows':
            result = subprocess.run(['route', 'print', '0.0.0.0'],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                # Cerca riga con 0.0.0.0
                for line in result.stdout.split('\n'):
                    if '0.0.0.0' in line and 'On-link' not in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            gateway = parts[2]
                            if validate_ip_address(gateway):
                                return gateway
        else:
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                # Cerca 'via <gateway>'
                match = re.search(r'via\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', result.stdout)
                if match:
                    return match.group(1)

    except Exception as e:
        print(f"Errore getting default gateway: {e}")

    return None


def is_port_open(host, port, timeout=3):
    """Verifica se una porta è aperta"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_open_ports(host, port_range=None, timeout=1):
    """Scansiona porte aperte su un host"""
    if port_range is None:
        # Porte comuni da testare
        port_range = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
                      1723, 3389, 5900, 8080, 8443, 10000]

    open_ports = []

    for port in port_range:
        if is_port_open(host, port, timeout):
            open_ports.append(port)

    return open_ports


def timestamp_to_datetime(timestamp):
    """Converte timestamp in datetime string"""
    try:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Unknown"


def get_file_age_days(filepath):
    """Ottiene età file in giorni"""
    try:
        import os
        from datetime import datetime

        mtime = os.path.getmtime(filepath)
        age_seconds = datetime.now().timestamp() - mtime
        return age_seconds / 86400  # Converti in giorni

    except Exception:
        return None