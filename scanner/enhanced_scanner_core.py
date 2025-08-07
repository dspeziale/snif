# scanner/enhanced_scanner_core.py - Enhanced version with Windows fixes
import platform
import subprocess
import xml.etree.ElementTree as ET
import os
import re
import socket
import ipaddress
import threading
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import logging
import time
import json


class EnhancedNetworkScanner:
    """Enhanced Network Scanner with improved Windows compatibility and error handling"""

    def __init__(self, config_manager, db_manager, cache_manager):
        self.config = config_manager
        self.db = db_manager
        self.cache = cache_manager
        self.setup_logging()

        # Windows-specific settings
        self.is_windows = platform.system().lower() == 'windows'
        self.nmap_capabilities = self.check_nmap_capabilities()

        # Performance settings
        self.max_concurrent_scans = self.config.get('network.parallel_scans', 3)
        self.scan_timeout = self.config.get('network.single_range_timeout', 120)

        self.logger.info(f"Scanner initialized - OS: {platform.system()}, Capabilities: {self.nmap_capabilities}")

    def setup_logging(self):
        """Enhanced logging setup"""
        log_file = self.config.get('logging.file', 'scanner/log/scanner.log')
        log_level = getattr(logging, self.config.get('logging.level', 'INFO'))

        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # File handler
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        # Setup logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def check_nmap_capabilities(self):
        """Enhanced nmap capability detection"""
        try:
            # Test basic nmap functionality
            result = subprocess.run(
                [self.config.get('nmap.path', 'nmap'), '--version'],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='replace'
            )

            if result.returncode != 0:
                self.logger.error("Nmap not found or not working")
                return None

            version_line = result.stdout.split('\n')[0] if result.stdout else ''
            self.logger.info(f"Nmap detected: {version_line}")

            # Test Windows-specific issues
            if self.is_windows:
                return self._test_windows_nmap()

            return "full"

        except Exception as e:
            self.logger.error(f"Error checking nmap capabilities: {e}")
            return None

    def _test_windows_nmap(self):
        """Test Windows-specific nmap functionality"""
        try:
            # Test basic ping scan on localhost
            test_cmd = [
                self.config.get('nmap.path', 'nmap'),
                '-sn',
                '-T2',
                '--host-timeout', '10s',
                '127.0.0.1'
            ]

            result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                timeout=15,
                encoding='utf-8',
                errors='replace'
            )

            if result.returncode == 0:
                return "full"
            elif "requires root privileges" in result.stderr.lower():
                self.logger.warning("Nmap requires administrator privileges")
                return "limited"
            elif result.returncode in [3221225725, -1073741571]:
                self.logger.warning("Windows nmap memory/stack issues detected")
                return "unstable"
            else:
                self.logger.warning(f"Nmap test failed: {result.stderr}")
                return "limited"

        except Exception as e:
            self.logger.error(f"Windows nmap test failed: {e}")
            return "limited"

    def get_scan_ranges(self):
        """Get scanning ranges with auto-detection fallback"""
        configured_ranges = self.config.get('network.scan_range', [])

        if not configured_ranges:
            self.logger.info("No ranges configured, auto-detecting local networks...")
            detected_ranges = self._detect_local_networks()
            if detected_ranges:
                self.config.set('network.scan_range', detected_ranges)
                return detected_ranges
            else:
                # Ultimate fallback
                fallback = "192.168.1.0/24"
                self.logger.warning(f"Using fallback range: {fallback}")
                return [fallback]

        return configured_ranges if isinstance(configured_ranges, list) else [configured_ranges]

    def _detect_local_networks(self):
        """Enhanced local network detection"""
        local_networks = []

        try:
            if self.is_windows:
                networks = self._detect_windows_networks()
            else:
                networks = self._detect_unix_networks()

            for network in networks:
                if self._validate_network_range(network):
                    local_networks.append(network)
                    self.logger.info(f"Detected local network: {network}")

        except Exception as e:
            self.logger.error(f"Error detecting local networks: {e}")

        return local_networks

    def _detect_windows_networks(self):
        """Detect Windows networks using ipconfig"""
        networks = []

        try:
            result = subprocess.run(
                ['ipconfig'],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='replace'
            )

            if result.returncode != 0:
                return networks

            # Parse ipconfig output for IPv4 addresses
            ip_pattern = r'IPv4.*?(\d+\.\d+\.\d+\.\d+)'
            matches = re.findall(ip_pattern, result.stdout)

            for ip in matches:
                try:
                    ip_obj = ipaddress.IPv4Address(ip)
                    if ip_obj.is_private and not ip_obj.is_loopback:
                        # Assume /24 subnet
                        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                        network_str = str(network)
                        if network_str not in networks:
                            networks.append(network_str)
                except:
                    continue

        except Exception as e:
            self.logger.debug(f"Error in Windows network detection: {e}")

        return networks

    def _detect_unix_networks(self):
        """Detect Unix/Linux networks using ip or ifconfig"""
        networks = []

        try:
            # Try 'ip addr' first (modern Linux)
            result = subprocess.run(
                ['ip', 'addr', 'show'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                # Fallback to ifconfig
                result = subprocess.run(
                    ['ifconfig'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            if result.returncode == 0:
                # Parse for CIDR notation networks
                cidr_pattern = r'inet (\d+\.\d+\.\d+\.\d+/\d+)'
                matches = re.findall(cidr_pattern, result.stdout)

                for match in matches:
                    try:
                        network = ipaddress.IPv4Network(match, strict=False)
                        if network.is_private and not network.is_loopback:
                            network_str = str(network)
                            if network_str not in networks:
                                networks.append(network_str)
                    except:
                        continue

        except Exception as e:
            self.logger.debug(f"Error in Unix network detection: {e}")

        return networks

    def run_discovery_scan(self):
        """Enhanced discovery scan with better error handling"""
        ranges = self.get_scan_ranges()
        self.logger.info(f"Starting discovery scan on {len(ranges)} ranges: {ranges}")

        # Register scan
        scan_id = self.db.add_scan_record('discovery', f"{len(ranges)} ranges")

        try:
            total_devices = 0
            successful_ranges = 0
            failed_ranges = []
            scan_results = []

            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=min(self.max_concurrent_scans, len(ranges))) as executor:
                future_to_range = {
                    executor.submit(self._scan_single_range_enhanced, range_ip): range_ip
                    for range_ip in ranges
                }

                for future in as_completed(future_to_range, timeout=self.scan_timeout * len(ranges)):
                    range_ip = future_to_range[future]
                    try:
                        result = future.result(timeout=self.scan_timeout)
                        total_devices += result['devices_found']
                        successful_ranges += 1
                        scan_results.append(result)

                        self.logger.info(
                            f"Range {range_ip}: {result['devices_found']} devices found "
                            f"(took {result.get('duration', 0):.1f}s)"
                        )
                    except Exception as e:
                        failed_ranges.append(range_ip)
                        self.logger.error(f"Failed to scan range {range_ip}: {e}")

            # Update scan record
            status_msg = f"Completed: {successful_ranges}/{len(ranges)} ranges, {total_devices} devices"
            if failed_ranges:
                status_msg += f". Failed: {failed_ranges}"

            self.db.update_scan_record(scan_id, 'completed', total_devices, status_msg)

            result = {
                'total_devices_found': total_devices,
                'ranges_scanned': successful_ranges,
                'failed_ranges': failed_ranges,
                'scan_results': scan_results
            }

            self.logger.info(f"Discovery scan completed: {total_devices} total devices found")
            return result

        except Exception as e:
            self.logger.error(f"Error in discovery scan: {e}")
            self.db.update_scan_record(scan_id, 'error', 0, str(e))
            raise

    def _scan_single_range_enhanced(self, scan_range):
        """Enhanced single range scanning with multiple fallback strategies"""
        start_time = time.time()
        self.logger.info(f"Scanning range {scan_range}")

        strategies = [
            self._scan_strategy_standard,
            self._scan_strategy_simple,
            self._scan_strategy_minimal
        ]

        last_error = None

        for i, strategy in enumerate(strategies):
            try:
                self.logger.debug(f"Trying strategy {i + 1} for range {scan_range}")
                result = strategy(scan_range)

                if result['devices_found'] > 0 or i == len(strategies) - 1:
                    duration = time.time() - start_time
                    result['duration'] = duration
                    result['strategy_used'] = i + 1
                    return result

            except Exception as e:
                last_error = e
                self.logger.warning(f"Strategy {i + 1} failed for {scan_range}: {e}")
                continue

        # All strategies failed
        duration = time.time() - start_time
        self.logger.error(f"All strategies failed for range {scan_range}: {last_error}")
        return {
            'range': scan_range,
            'devices_found': 0,
            'duration': duration,
            'error': str(last_error),
            'strategy_used': 'failed'
        }

    def _scan_strategy_standard(self, scan_range):
        """Standard nmap discovery strategy"""
        return self._execute_nmap_scan(scan_range, {
            'args': ['-sn', '-PE', '-PP', '-PS80,443,22,23'],
            'timing': '-T3',
            'timeout': '30s',
            'retries': '2'
        })

    def _scan_strategy_simple(self, scan_range):
        """Simplified strategy for problematic systems"""
        return self._execute_nmap_scan(scan_range, {
            'args': ['-sn', '-PE'],
            'timing': '-T2',
            'timeout': '60s',
            'retries': '1'
        })

    def _scan_strategy_minimal(self, scan_range):
        """Minimal strategy as last resort"""
        return self._execute_nmap_scan(scan_range, {
            'args': ['-sn'],
            'timing': '-T1',
            'timeout': '90s',
            'retries': '1'
        })

    def _execute_nmap_scan(self, scan_range, options):
        """Execute nmap scan with given options"""
        # Generate safe filename
        safe_range = scan_range.replace('/', '_').replace('.', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        xml_file = f"scanner/xml/discovery_{safe_range}_{timestamp}.xml"

        # Ensure XML directory exists
        os.makedirs(os.path.dirname(xml_file), exist_ok=True)

        # Build nmap command
        nmap_cmd = [
            self.config.get('nmap.path', 'nmap'),
            *options['args'],
            options['timing'],
            '--host-timeout', options['timeout'],
            '--max-retries', options['retries'],
            '-oX', xml_file,
            scan_range
        ]

        self.logger.debug(f"Executing nmap: {' '.join(nmap_cmd)}")

        # Execute with proper encoding handling
        result = subprocess.run(
            nmap_cmd,
            capture_output=True,
            text=True,
            timeout=self.scan_timeout,
            encoding='utf-8',
            errors='replace'
        )

        # Check result
        if result.returncode not in [0, 1]:  # 0=success, 1=warning
            raise Exception(f"Nmap failed (code {result.returncode}): {result.stderr}")

        # Parse results
        devices_found = self._parse_discovery_xml_enhanced(xml_file)

        return {
            'range': scan_range,
            'devices_found': devices_found,
            'xml_file': xml_file,
            'nmap_returncode': result.returncode
        }

    def _parse_discovery_xml_enhanced(self, xml_file):
        """Enhanced XML parsing with better error handling"""
        if not os.path.exists(xml_file):
            self.logger.warning(f"XML file not found: {xml_file}")
            return 0

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            devices_found = 0

            for host in root.findall('host'):
                try:
                    # Check host status
                    status = host.find('status')
                    if status is None or status.get('state') != 'up':
                        continue

                    # Extract IP address
                    address_elem = host.find(".//address[@addrtype='ipv4']")
                    if address_elem is None:
                        continue

                    ip = address_elem.get('addr')
                    if not ip:
                        continue

                    # Extract MAC address and vendor
                    mac = None
                    vendor = None
                    mac_elem = host.find(".//address[@addrtype='mac']")
                    if mac_elem is not None:
                        mac = mac_elem.get('addr')
                        vendor = mac_elem.get('vendor', '')

                        # Try to get vendor from cache if not provided
                        if not vendor and mac:
                            vendor = self.cache.get_vendor_from_mac(mac) or 'Unknown'

                    # Extract hostname
                    hostname = self._extract_hostname(host, ip)

                    # Estimate device type
                    device_type = self._estimate_device_type_enhanced(ip, hostname, mac, vendor)

                    # Add to database
                    device_id = self.db.add_device(
                        ip=ip,
                        mac=mac,
                        hostname=hostname,
                        vendor=vendor,
                        device_type=device_type
                    )

                    devices_found += 1
                    self.logger.debug(f"Device added: {ip} [{device_type}] - {hostname or 'No hostname'}")

                except Exception as e:
                    self.logger.error(f"Error processing host in XML: {e}")
                    continue

            self.logger.info(f"Parsed XML {xml_file}: {devices_found} devices")
            return devices_found

        except ET.ParseError as e:
            self.logger.error(f"XML parsing error in {xml_file}: {e}")
            return 0
        except Exception as e:
            self.logger.error(f"Error parsing discovery XML {xml_file}: {e}")
            return 0

    def _extract_hostname(self, host_elem, ip):
        """Extract hostname from nmap XML with DNS fallback"""
        # Try to get hostname from nmap results
        hostnames = host_elem.findall(".//hostname")
        if hostnames:
            for hn in hostnames:
                name = hn.get('name', '').strip()
                if name and name != ip and not name.startswith(ip):
                    return name

        # Fallback to DNS resolution
        try:
            socket.setdefaulttimeout(2)
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname and hostname != ip:
                return hostname
        except:
            pass
        finally:
            socket.setdefaulttimeout(None)

        return None

    def _estimate_device_type_enhanced(self, ip, hostname=None, mac=None, vendor=None):
        """Enhanced device type estimation"""
        # Hostname analysis
        if hostname:
            hostname_lower = hostname.lower()

            # Router/Gateway patterns
            if any(term in hostname_lower for term in [
                'router', 'gateway', 'gw', 'rt', 'edge', 'border'
            ]):
                return 'router'

            # Switch patterns
            elif any(term in hostname_lower for term in [
                'switch', 'sw', 'layer2', 'l2'
            ]):
                return 'switch'

            # Access Point patterns
            elif any(term in hostname_lower for term in [
                'ap', 'wifi', 'wireless', 'wlan', 'access'
            ]):
                return 'access_point'

            # Server patterns
            elif any(term in hostname_lower for term in [
                'server', 'srv', 'web', 'mail', 'dns', 'dhcp', 'file', 'db', 'database'
            ]):
                return 'server'

            # Printer patterns
            elif any(term in hostname_lower for term in [
                'printer', 'print', 'canon', 'hp', 'epson', 'brother', 'xerox'
            ]):
                return 'printer'

            # Desktop patterns
            elif any(term in hostname_lower for term in [
                'desktop', 'pc', 'workstation', 'ws', 'computer'
            ]):
                return 'desktop'

            # Mobile patterns
            elif any(term in hostname_lower for term in [
                'phone', 'mobile', 'android', 'iphone', 'ipad', 'tablet'
            ]):
                return 'mobile'

        # Vendor analysis
        if vendor:
            vendor_lower = vendor.lower()

            # Network equipment vendors
            if any(term in vendor_lower for term in [
                'cisco', 'juniper', 'mikrotik', 'ubiquiti', 'netgear', 'd-link', 'linksys'
            ]):
                return 'network_device'

            # Printer vendors
            elif any(term in vendor_lower for term in [
                'hewlett-packard', 'hp', 'canon', 'epson', 'brother', 'xerox', 'samsung'
            ]):
                return 'printer'

            # Apple devices
            elif 'apple' in vendor_lower:
                return 'apple_device'

            # Mobile device vendors
            elif any(term in vendor_lower for term in [
                'samsung', 'lg', 'sony', 'huawei', 'xiaomi'
            ]):
                return 'mobile'

        # IP-based analysis
        if ip:
            try:
                last_octet = int(ip.split('.')[-1])

                # Common gateway IPs
                if last_octet in [1, 254]:
                    return 'router'

                # Server range
                elif 10 <= last_octet <= 50:
                    return 'server'

                # Printer range
                elif 200 <= last_octet <= 220:
                    return 'printer'

                # Desktop range
                elif 100 <= last_octet <= 199:
                    return 'desktop'

            except:
                pass

        return 'unknown'

    def _validate_network_range(self, network_range):
        """Validate network range format"""
        try:
            ipaddress.IPv4Network(network_range, strict=False)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    def get_scan_ranges_info(self):
        """Get detailed information about configured scan ranges"""
        scan_ranges = self.get_scan_ranges()
        ranges_info = []

        for scan_range in scan_ranges:
            try:
                network = ipaddress.IPv4Network(scan_range, strict=False)
                info = {
                    'range': scan_range,
                    'network_address': str(network.network_address),
                    'broadcast_address': str(network.broadcast_address),
                    'num_hosts': network.num_addresses - 2,
                    'is_private': network.is_private,
                    'valid': True
                }
            except Exception as e:
                info = {
                    'range': scan_range,
                    'error': str(e),
                    'valid': False
                }

            ranges_info.append(info)

        return ranges_info

    # Additional utility methods for services, OS, vulnerability, and SNMP scanning
    # would follow the same pattern with enhanced error handling...

    def run_services_scan(self, device_id):
        """Enhanced services scan"""
        device = self._get_device_by_id(device_id)
        if not device:
            raise Exception("Device not found")

        ip = device['ip_address']
        self.logger.info(f"Starting services scan on {ip}")

        scan_id = self.db.add_scan_record('services', ip)

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            xml_file = f"scanner/xml/services_{ip.replace('.', '_')}_{timestamp}.xml"

            # Ensure directory exists
            os.makedirs(os.path.dirname(xml_file), exist_ok=True)

            nmap_cmd = [
                self.config.get('nmap.path', 'nmap'),
                '-sS',
                '-sV',
                '--version-intensity', '5',
                '-T3',
                '--host-timeout', '300s',
                '-oX', xml_file,
                ip
            ]

            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=600,
                encoding='utf-8',
                errors='replace'
            )

            if result.returncode not in [0, 1]:
                raise Exception(f"Nmap services scan failed: {result.stderr}")

            # Parse results
            services_found = self._parse_services_xml(xml_file, device_id)

            self.db.update_scan_record(scan_id, 'completed', services_found)

            self.logger.info(f"Services scan completed on {ip}: {services_found} services found")
            return {'services_found': services_found, 'xml_file': xml_file}

        except Exception as e:
            self.logger.error(f"Error in services scan for {ip}: {e}")
            self.db.update_scan_record(scan_id, 'error', 0, str(e))
            raise

    def _get_device_by_id(self, device_id):
        """Get device information by ID"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
        device = cursor.fetchone()
        conn.close()
        return dict(device) if device else None

    def _parse_services_xml(self, xml_file, device_id):
        """Parse services scan XML results"""
        if not os.path.exists(xml_file):
            return 0

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            services_found = 0

            for host in root.findall('host'):
                ports = host.find('ports')
                if ports is None:
                    continue

                for port in ports.findall('port'):
                    try:
                        port_num = int(port.get('portid'))
                        protocol = port.get('protocol')

                        state_elem = port.find('state')
                        if state_elem is None or state_elem.get('state') != 'open':
                            continue

                        # Extract service information
                        service_elem = port.find('service')
                        service_name = None
                        version = None

                        if service_elem is not None:
                            service_name = service_elem.get('name')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')

                            # Combine product and version
                            if product and version:
                                version = f"{product} {version}"
                            elif product:
                                version = product

                        # Add service to database
                        self.db.add_service(
                            device_id=device_id,
                            port=port_num,
                            protocol=protocol,
                            service_name=service_name,
                            version=version,
                            state='open'
                        )
                        services_found += 1

                    except Exception as e:
                        self.logger.error(f"Error parsing service port: {e}")
                        continue

            return services_found

        except Exception as e:
            self.logger.error(f"Error parsing services XML {xml_file}: {e}")
            return 0