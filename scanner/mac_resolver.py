# ===================================================================
# scanner/mac_resolver.py - Risolutore MAC address per Windows
import subprocess
import re
import platform
import socket
import struct


class MacResolver:
    """Risolutore MAC address ottimizzato per Windows"""

    def __init__(self):
        self.os_type = platform.system().lower()
        self.arp_cache = {}

    def get_mac_address(self, ip_address):
        """Ottiene MAC address per un IP usando vari metodi"""

        # Metodo 1: Tabella ARP
        mac = self._get_mac_from_arp(ip_address)
        if mac:
            return mac

        # Metodo 2: Ping + ARP (forza entry nella tabella ARP)
        if self._ping_host(ip_address):
            mac = self._get_mac_from_arp(ip_address)
            if mac:
                return mac

        # Metodo 3: NetBIOS (Windows)
        if self.os_type == 'windows':
            mac = self._get_mac_from_netbios(ip_address)
            if mac:
                return mac

        return None

    def _ping_host(self, ip_address):
        """Ping host per forzare entry ARP"""
        try:
            if self.os_type == 'windows':
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip_address],
                    capture_output=True,
                    timeout=5
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip_address],
                    capture_output=True,
                    timeout=5
                )

            return result.returncode == 0

        except Exception:
            return False

    def _get_mac_from_arp(self, ip_address):
        """Ottiene MAC dalla tabella ARP"""
        try:
            if self.os_type == 'windows':
                # Windows ARP command
                result = subprocess.run(
                    ['arp', '-a'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    return self._parse_windows_arp(result.stdout, ip_address)

            else:
                # Linux/Unix ARP command
                result = subprocess.run(
                    ['arp', '-a'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    return self._parse_unix_arp(result.stdout, ip_address)

        except Exception as e:
            print(f"Errore ARP lookup: {e}")

        return None

    def _parse_windows_arp(self, arp_output, target_ip):
        """Parse output ARP di Windows"""
        try:
            lines = arp_output.split('\n')
            for line in lines:
                if target_ip in line:
                    # Formato Windows: IP-Address Physical-Address Type
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        mac = parts[1].strip()

                        if ip == target_ip and self._is_valid_mac(mac):
                            return self._normalize_mac(mac)

        except Exception as e:
            print(f"Errore parse Windows ARP: {e}")

        return None

    def _parse_unix_arp(self, arp_output, target_ip):
        """Parse output ARP di Unix/Linux"""
        try:
            lines = arp_output.split('\n')
            for line in lines:
                if target_ip in line:
                    # Cerca pattern MAC address
                    mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
                    match = re.search(mac_pattern, line)

                    if match:
                        mac = match.group()
                        return self._normalize_mac(mac)

        except Exception as e:
            print(f"Errore parse Unix ARP: {e}")

        return None

    def _get_mac_from_netbios(self, ip_address):
        """Ottiene MAC tramite NetBIOS (Windows)"""
        try:
            # Usa nbtstat per Windows
            result = subprocess.run(
                ['nbtstat', '-A', ip_address],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Cerca MAC address nell'output
                mac_pattern = r'([0-9a-fA-F]{2}[-]){5}[0-9a-fA-F]{2}'
                match = re.search(mac_pattern, result.stdout)

                if match:
                    mac = match.group()
                    return self._normalize_mac(mac)

        except Exception as e:
            print(f"Errore NetBIOS lookup: {e}")

        return None

    def _is_valid_mac(self, mac):
        """Verifica se MAC address è valido"""
        if not mac or len(mac) < 12:
            return False

        # Rimuovi separatori
        clean_mac = re.sub(r'[:-]', '', mac)

        # Verifica lunghezza e caratteri hex
        return len(clean_mac) == 12 and re.match(r'^[0-9a-fA-F]{12}$', clean_mac)

    def _normalize_mac(self, mac):
        """Normalizza formato MAC address"""
        if not mac:
            return None

        # Rimuovi caratteri non hex
        clean_mac = re.sub(r'[^0-9a-fA-F]', '', mac.upper())

        if len(clean_mac) != 12:
            return None

        # Formato standard con :
        return ':'.join(clean_mac[i:i + 2] for i in range(0, 12, 2))

    def get_local_interfaces(self):
        """Ottiene interfacce di rete locali (Windows)"""
        interfaces = []

        try:
            if self.os_type == 'windows':
                result = subprocess.run(
                    ['ipconfig', '/all'],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    interfaces = self._parse_ipconfig(result.stdout)

            else:
                result = subprocess.run(
                    ['ifconfig', '-a'],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    interfaces = self._parse_ifconfig(result.stdout)

        except Exception as e:
            print(f"Errore getting local interfaces: {e}")

        return interfaces

    def _parse_ipconfig(self, output):
        """Parse output ipconfig Windows"""
        interfaces = []
        current_interface = {}

        try:
            lines = output.split('\n')
            for line in lines:
                line = line.strip()

                if 'adapter' in line.lower():
                    # Nuovo adapter
                    if current_interface:
                        interfaces.append(current_interface)

                    current_interface = {
                        'name': line,
                        'ip_addresses': [],
                        'mac_address': None
                    }

                elif 'Physical Address' in line or 'Indirizzo fisico' in line:
                    # MAC address
                    parts = line.split(':')
                    if len(parts) >= 2:
                        mac = ':'.join(parts[1:]).strip()
                        current_interface['mac_address'] = self._normalize_mac(mac)

                elif 'IPv4 Address' in line or 'Indirizzo IPv4' in line:
                    # IP address
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        current_interface['ip_addresses'].append(ip_match.group(1))

            if current_interface:
                interfaces.append(current_interface)

        except Exception as e:
            print(f"Errore parse ipconfig: {e}")

        return interfaces

    def _parse_ifconfig(self, output):
        """Parse output ifconfig Unix/Linux"""
        interfaces = []
        current_interface = {}

        try:
            lines = output.split('\n')
            for line in lines:
                if not line.startswith(' ') and ':' in line:
                    # Nuovo interface
                    if current_interface:
                        interfaces.append(current_interface)

                    current_interface = {
                        'name': line.split(':')[0],
                        'ip_addresses': [],
                        'mac_address': None
                    }

                elif 'ether' in line.lower():
                    # MAC address
                    mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                    if mac_match:
                        current_interface['mac_address'] = self._normalize_mac(mac_match.group())

                elif 'inet ' in line:
                    # IP address
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        current_interface['ip_addresses'].append(ip_match.group(1))

            if current_interface:
                interfaces.append(current_interface)

        except Exception as e:
            print(f"Errore parse ifconfig: {e}")

        return interfaces