"""
SNMP Parser Extension
Specialized parser for SNMP-related data from Nmap XML files
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from nmap_scanner_db import NmapScannerDB

class SNMPDataParser:
    """Parser for extracting and storing SNMP-specific data"""

    def __init__(self, db: NmapScannerDB):
        self.db = db
        self.logger = logging.getLogger(__name__)

    def parse_snmp_processes(self, script_output: str, host_id: int) -> int:
        """Parse SNMP process enumeration output"""
        if not script_output:
            return 0

        processes_inserted = 0

        # Parse process table format from snmp-processes script
        lines = script_output.strip().split('\n')
        current_process = {}

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for process ID patterns
            pid_match = re.search(r'Process ID: (\d+)', line)
            if pid_match:
                if current_process:
                    self._insert_process(current_process, host_id)
                    processes_inserted += 1
                current_process = {'process_id': int(pid_match.group(1))}
                continue

            # Look for process name
            name_match = re.search(r'Name: (.+)', line)
            if name_match:
                current_process['process_name'] = name_match.group(1).strip()
                continue

            # Look for process path
            path_match = re.search(r'Path: (.+)', line)
            if path_match:
                current_process['process_path'] = path_match.group(1).strip()
                continue

            # Look for process arguments
            args_match = re.search(r'Args: (.+)', line)
            if args_match:
                current_process['process_args'] = args_match.group(1).strip()
                continue

        # Insert the last process if exists
        if current_process:
            self._insert_process(current_process, host_id)
            processes_inserted += 1

        return processes_inserted

    def _insert_process(self, process_data: Dict, host_id: int):
        """Insert a single process into the database"""
        try:
            self.db.conn.execute("""
            INSERT INTO processes (
                host_id, process_id, process_name, process_path, process_args
            ) VALUES (?, ?, ?, ?, ?)
            """, (
                host_id,
                process_data.get('process_id'),
                process_data.get('process_name'),
                process_data.get('process_path'),
                process_data.get('process_args')
            ))
        except Exception as e:
            self.logger.error(f"Error inserting process: {e}")

    def parse_snmp_netstat(self, script_output: str, host_id: int) -> int:
        """Parse SNMP netstat output"""
        if not script_output:
            return 0

        connections_inserted = 0
        lines = script_output.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line or not line.startswith(('TCP', 'UDP')):
                continue

            # Parse network connection format: TCP  local_ip:port   remote_ip:port
            parts = line.split()
            if len(parts) >= 3:
                protocol = parts[0]
                local_part = parts[1]
                remote_part = parts[2] if len(parts) > 2 else "0.0.0.0:0"

                # Parse local address and port
                local_addr, local_port = self._parse_address_port(local_part)
                remote_addr, remote_port = self._parse_address_port(remote_part)

                # Determine connection state
                state = "LISTENING" if remote_part == "0.0.0.0:0" else "ESTABLISHED"

                try:
                    self.db.conn.execute("""
                    INSERT INTO network_connections (
                        host_id, protocol, local_address, local_port,
                        remote_address, remote_port, state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        host_id, protocol, local_addr, local_port,
                        remote_addr, remote_port, state
                    ))
                    connections_inserted += 1
                except Exception as e:
                    self.logger.error(f"Error inserting network connection: {e}")

        return connections_inserted

    def _parse_address_port(self, addr_port_str: str) -> Tuple[str, int]:
        """Parse address:port string"""
        try:
            if ':' in addr_port_str:
                addr, port = addr_port_str.rsplit(':', 1)
                return addr, int(port)
            else:
                return addr_port_str, 0
        except (ValueError, AttributeError):
            return "0.0.0.0", 0

    def parse_snmp_system_info(self, script_elements: List[Dict], host_id: int) -> bool:
        """Parse SNMP system information"""
        try:
            # Extract system information from script elements
            system_info = {}

            for elem in script_elements:
                key = elem.get('elem_key', '').lower()
                value = elem.get('elem_value', '')

                if key == 'system.sysdescr.0':
                    system_info['system_description'] = value
                elif key == 'system.sysuptime.0':
                    # Parse uptime (usually in timeticks)
                    uptime_match = re.search(r'\((\d+)\)', value)
                    if uptime_match:
                        system_info['system_uptime'] = int(uptime_match.group(1))
                elif key == 'system.syscontact.0':
                    system_info['system_contact'] = value
                elif key == 'system.sysname.0':
                    system_info['system_name'] = value
                elif key == 'system.syslocation.0':
                    system_info['system_location'] = value

            if system_info:
                self.db.conn.execute("""
                INSERT INTO snmp_info (
                    host_id, system_description, system_uptime, system_contact,
                    system_name, system_location
                ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    host_id,
                    system_info.get('system_description'),
                    system_info.get('system_uptime'),
                    system_info.get('system_contact'),
                    system_info.get('system_name'),
                    system_info.get('system_location')
                ))
                return True

        except Exception as e:
            self.logger.error(f"Error parsing SNMP system info: {e}")

        return False

    def extract_process_names_from_script_tables(self, script_id: int, host_id: int) -> int:
        """Extract process names from script table structures"""
        try:
            # Query script elements for process information
            cursor = self.db.conn.execute("""
            SELECT elem_key, elem_value, parent_table_key
            FROM script_elements 
            WHERE script_id = ? AND elem_key = 'Name'
            """, (script_id,))

            processes_inserted = 0

            for row in cursor.fetchall():
                elem_key, elem_value, parent_table_key = row

                # Extract process ID from parent table key if available
                process_id = None
                if parent_table_key:
                    try:
                        process_id = int(parent_table_key)
                    except ValueError:
                        process_id = None

                # Insert process information
                try:
                    self.db.conn.execute("""
                    INSERT INTO processes (host_id, process_id, process_name)
                    VALUES (?, ?, ?)
                    """, (host_id, process_id, elem_value))
                    processes_inserted += 1
                except Exception as e:
                    self.logger.error(f"Error inserting process from table: {e}")

            return processes_inserted

        except Exception as e:
            self.logger.error(f"Error extracting process names: {e}")
            return 0

    def get_host_processes(self, host_id: int) -> List[Dict]:
        """Get all processes for a specific host"""
        try:
            cursor = self.db.conn.execute("""
            SELECT process_id, process_name, process_path, process_args
            FROM processes
            WHERE host_id = ?
            ORDER BY process_id
            """, (host_id,))

            processes = []
            for row in cursor.fetchall():
                processes.append({
                    'process_id': row[0],
                    'process_name': row[1],
                    'process_path': row[2],
                    'process_args': row[3]
                })

            return processes

        except Exception as e:
            self.logger.error(f"Error getting host processes: {e}")
            return []

    def get_host_network_connections(self, host_id: int) -> List[Dict]:
        """Get all network connections for a specific host"""
        try:
            cursor = self.db.conn.execute("""
            SELECT protocol, local_address, local_port, remote_address, remote_port, state
            FROM network_connections
            WHERE host_id = ?
            ORDER BY protocol, local_port
            """, (host_id,))

            connections = []
            for row in cursor.fetchall():
                connections.append({
                    'protocol': row[0],
                    'local_address': row[1],
                    'local_port': row[2],
                    'remote_address': row[3],
                    'remote_port': row[4],
                    'state': row[5]
                })

            return connections

        except Exception as e:
            self.logger.error(f"Error getting network connections: {e}")
            return []

    def get_snmp_system_info(self, host_id: int) -> Optional[Dict]:
        """Get SNMP system information for a specific host"""
        try:
            cursor = self.db.conn.execute("""
            SELECT system_description, system_uptime, system_contact,
                   system_name, system_location
            FROM snmp_info
            WHERE host_id = ?
            """, (host_id,))

            row = cursor.fetchone()
            if row:
                return {
                    'system_description': row[0],
                    'system_uptime': row[1],
                    'system_contact': row[2],
                    'system_name': row[3],
                    'system_location': row[4]
                }

            return None

        except Exception as e:
            self.logger.error(f"Error getting SNMP system info: {e}")
            return None

    def parse_snmp_interfaces(self, script_output: str, host_id: int) -> int:
        """Parse SNMP network interfaces information"""
        if not script_output:
            return 0

        interfaces_parsed = 0
        lines = script_output.strip().split('\n')
        current_interface = {}

        for line in lines:
            line = line.strip()

            if not line:
                if current_interface:
                    self._store_interface_info(current_interface, host_id)
                    interfaces_parsed += 1
                    current_interface = {}
                continue

            # Parse interface information
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                current_interface[key] = value

        # Insert last interface if exists
        if current_interface:
            self._store_interface_info(current_interface, host_id)
            interfaces_parsed += 1

        return interfaces_parsed

    def _store_interface_info(self, interface_data: Dict, host_id: int):
        """Store network interface information"""
        try:
            # For now, store as JSON in script_elements
            # In future versions, could have dedicated interfaces table
            interface_json = str(interface_data)

            self.db.conn.execute("""
            INSERT INTO script_elements (script_id, elem_key, elem_value, parent_table_key)
            VALUES (?, ?, ?, ?)
            """, (
                None,  # No specific script_id for this data
                f"interface_{interface_data.get('index', 'unknown')}",
                interface_json,
                f"host_{host_id}_interfaces"
            ))
        except Exception as e:
            self.logger.error(f"Error storing interface info: {e}")

    def parse_snmp_storage(self, script_output: str, host_id: int) -> int:
        """Parse SNMP storage/disk information"""
        if not script_output:
            return 0

        storage_devices = 0
        lines = script_output.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for storage device patterns
            storage_match = re.search(r'(\d+)\s+(.+?)\s+(\d+)\s+(\d+)', line)
            if storage_match:
                index, description, size, used = storage_match.groups()

                try:
                    self.db.conn.execute("""
                    INSERT INTO script_elements (script_id, elem_key, elem_value, parent_table_key)
                    VALUES (?, ?, ?, ?)
                    """, (
                        None,
                        f"storage_{index}",
                        f"Description: {description}, Size: {size}, Used: {used}",
                        f"host_{host_id}_storage"
                    ))
                    storage_devices += 1
                except Exception as e:
                    self.logger.error(f"Error storing storage info: {e}")

        return storage_devices

    def parse_snmp_users(self, script_output: str, host_id: int) -> int:
        """Parse SNMP user enumeration"""
        if not script_output:
            return 0

        users_found = 0
        lines = script_output.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for user patterns
            user_match = re.search(r'User:\s*(.+)', line)
            if user_match:
                username = user_match.group(1).strip()

                try:
                    self.db.conn.execute("""
                    INSERT INTO script_elements (script_id, elem_key, elem_value, parent_table_key)
                    VALUES (?, ?, ?, ?)
                    """, (
                        None,
                        f"user_{users_found}",
                        username,
                        f"host_{host_id}_users"
                    ))
                    users_found += 1
                except Exception as e:
                    self.logger.error(f"Error storing user info: {e}")

        return users_found

    def parse_snmp_software(self, script_output: str, host_id: int) -> int:
        """Parse SNMP installed software enumeration"""
        if not script_output:
            return 0

        software_items = 0
        lines = script_output.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for software patterns
            software_match = re.search(r'(\d+)\s+(.+)', line)
            if software_match:
                index, software_name = software_match.groups()

                try:
                    self.db.conn.execute("""
                    INSERT INTO script_elements (script_id, elem_key, elem_value, parent_table_key)
                    VALUES (?, ?, ?, ?)
                    """, (
                        None,
                        f"software_{index}",
                        software_name.strip(),
                        f"host_{host_id}_software"
                    ))
                    software_items += 1
                except Exception as e:
                    self.logger.error(f"Error storing software info: {e}")

        return software_items

    def get_host_snmp_summary(self, host_id: int) -> Dict:
        """Get complete SNMP summary for a host"""
        try:
            summary = {
                'system_info': self.get_snmp_system_info(host_id),
                'processes': self.get_host_processes(host_id),
                'network_connections': self.get_host_network_connections(host_id),
                'interfaces': self._get_host_interfaces(host_id),
                'storage': self._get_host_storage(host_id),
                'users': self._get_host_users(host_id),
                'software': self._get_host_software(host_id)
            }

            return summary

        except Exception as e:
            self.logger.error(f"Error getting SNMP summary for host {host_id}: {e}")
            return {}

    def _get_host_interfaces(self, host_id: int) -> List[Dict]:
        """Get network interfaces for a host"""
        try:
            cursor = self.db.conn.execute("""
            SELECT elem_key, elem_value
            FROM script_elements
            WHERE parent_table_key = ? AND elem_key LIKE 'interface_%'
            """, (f"host_{host_id}_interfaces",))

            interfaces = []
            for row in cursor.fetchall():
                try:
                    # Parse back the stored interface data
                    interface_data = eval(row[1])  # Safe since we stored it ourselves
                    interfaces.append(interface_data)
                except:
                    # Fallback if eval fails
                    interfaces.append({'name': row[0], 'info': row[1]})

            return interfaces

        except Exception as e:
            self.logger.error(f"Error getting interfaces for host {host_id}: {e}")
            return []

    def _get_host_storage(self, host_id: int) -> List[Dict]:
        """Get storage devices for a host"""
        try:
            cursor = self.db.conn.execute("""
            SELECT elem_key, elem_value
            FROM script_elements
            WHERE parent_table_key = ? AND elem_key LIKE 'storage_%'
            """, (f"host_{host_id}_storage",))

            storage_devices = []
            for row in cursor.fetchall():
                storage_devices.append({
                    'device': row[0],
                    'info': row[1]
                })

            return storage_devices

        except Exception as e:
            self.logger.error(f"Error getting storage for host {host_id}: {e}")
            return []

    def _get_host_users(self, host_id: int) -> List[str]:
        """Get users for a host"""
        try:
            cursor = self.db.conn.execute("""
            SELECT elem_value
            FROM script_elements
            WHERE parent_table_key = ? AND elem_key LIKE 'user_%'
            """, (f"host_{host_id}_users",))

            users = [row[0] for row in cursor.fetchall()]
            return users

        except Exception as e:
            self.logger.error(f"Error getting users for host {host_id}: {e}")
            return []

    def _get_host_software(self, host_id: int) -> List[str]:
        """Get installed software for a host"""
        try:
            cursor = self.db.conn.execute("""
            SELECT elem_value
            FROM script_elements
            WHERE parent_table_key = ? AND elem_key LIKE 'software_%'
            """, (f"host_{host_id}_software",))

            software = [row[0] for row in cursor.fetchall()]
            return software

        except Exception as e:
            self.logger.error(f"Error getting software for host {host_id}: {e}")
            return []

    def generate_snmp_report(self, host_id: int = None) -> Dict:
        """Generate comprehensive SNMP report"""
        try:
            if host_id:
                # Report for specific host
                return {
                    'host_id': host_id,
                    'snmp_data': self.get_host_snmp_summary(host_id)
                }
            else:
                # Report for all hosts with SNMP data
                cursor = self.db.conn.execute("""
                SELECT DISTINCT host_id FROM snmp_info
                """)

                hosts_with_snmp = [row[0] for row in cursor.fetchall()]

                report = {
                    'summary': {
                        'total_hosts_with_snmp': len(hosts_with_snmp),
                        'total_processes': self._count_total_processes(),
                        'total_connections': self._count_total_connections()
                    },
                    'hosts': []
                }

                for hid in hosts_with_snmp:
                    host_data = self.get_host_snmp_summary(hid)

                    # Get host IP for context
                    cursor = self.db.conn.execute("""
                    SELECT ip_address FROM hosts WHERE id = ?
                    """, (hid,))

                    host_ip = cursor.fetchone()
                    host_ip = host_ip[0] if host_ip else "Unknown"

                    report['hosts'].append({
                        'host_id': hid,
                        'ip_address': host_ip,
                        'snmp_data': host_data
                    })

                return report

        except Exception as e:
            self.logger.error(f"Error generating SNMP report: {e}")
            return {}

    def _count_total_processes(self) -> int:
        """Count total processes across all hosts"""
        try:
            cursor = self.db.conn.execute("SELECT COUNT(*) FROM processes")
            return cursor.fetchone()[0]
        except:
            return 0

    def _count_total_connections(self) -> int:
        """Count total network connections across all hosts"""
        try:
            cursor = self.db.conn.execute("SELECT COUNT(*) FROM network_connections")
            return cursor.fetchone()[0]
        except:
            return 0

    def export_snmp_data_csv(self, output_file: str) -> bool:
        """Export SNMP data to CSV format"""
        try:
            import csv
            import os

            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                # Write SNMP system info
                writer = csv.writer(csvfile)
                writer.writerow(['Type', 'Host_IP', 'Host_ID', 'Data'])

                # Get all hosts with SNMP data
                cursor = self.db.conn.execute("""
                SELECT h.ip_address, si.host_id, si.system_name, si.system_description,
                       si.system_contact, si.system_location, si.system_uptime
                FROM snmp_info si
                JOIN hosts h ON si.host_id = h.id
                """)

                for row in cursor.fetchall():
                    ip, host_id, name, desc, contact, location, uptime = row
                    writer.writerow(['SYSTEM_INFO', ip, host_id,
                                   f"Name: {name}, Desc: {desc}, Contact: {contact}, Location: {location}, Uptime: {uptime}"])

                # Write process data
                cursor = self.db.conn.execute("""
                SELECT h.ip_address, p.host_id, p.process_name, p.process_id, p.process_path
                FROM processes p
                JOIN hosts h ON p.host_id = h.id
                WHERE p.process_name IS NOT NULL
                """)

                for row in cursor.fetchall():
                    ip, host_id, name, pid, path = row
                    writer.writerow(['PROCESS', ip, host_id, f"PID: {pid}, Name: {name}, Path: {path}"])

                # Write connection data
                cursor = self.db.conn.execute("""
                SELECT h.ip_address, nc.host_id, nc.protocol, nc.local_address, 
                       nc.local_port, nc.remote_address, nc.remote_port, nc.state
                FROM network_connections nc
                JOIN hosts h ON nc.host_id = h.id
                """)

                for row in cursor.fetchall():
                    ip, host_id, proto, local_addr, local_port, remote_addr, remote_port, state = row
                    writer.writerow(['CONNECTION', ip, host_id,
                                   f"{proto} {local_addr}:{local_port} -> {remote_addr}:{remote_port} ({state})"])

            self.logger.info(f"SNMP data exported to {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error exporting SNMP data to CSV: {e}")
            return False