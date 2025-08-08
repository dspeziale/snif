"""
SNMP Data Parser - Versione corretta
Gestisce correttamente i dati SNMP strutturati presenti nei file XML di Nmap
"""

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import re

class FixedSNMPParser:
    """Parser corretto per i dati SNMP da file XML Nmap"""

    def __init__(self, db_connection):
        self.db = db_connection
        self.logger = logging.getLogger(__name__)

    def parse_snmp_script(self, script_element: ET.Element, port_id: int, host_id: int):
        """Parse specifico per script SNMP basato sul tipo"""
        script_id = script_element.get('id', '')

        if script_id == 'snmp-win32-services':
            return self._parse_win32_services(script_element, host_id)
        elif script_id == 'snmp-processes':
            return self._parse_processes(script_element, host_id)
        elif script_id == 'snmp-win32-software':
            return self._parse_win32_software(script_element, host_id)
        elif script_id == 'snmp-win32-users':
            return self._parse_win32_users(script_element, host_id)
        elif script_id == 'snmp-interfaces':
            return self._parse_interfaces(script_element, host_id)
        elif script_id == 'snmp-netstat':
            return self._parse_netstat(script_element, host_id)
        elif script_id == 'snmp-sysdescr':
            return self._parse_system_description(script_element, host_id)
        elif script_id == 'snmp-win32-shares':
            return self._parse_win32_shares(script_element, host_id)

        return 0

    def _parse_win32_services(self, script_element: ET.Element, host_id: int) -> int:
        """Parse dei servizi Windows da SNMP"""
        services_parsed = 0

        # Parsing dai <elem> diretti (lista servizi)
        for elem in script_element.findall('elem'):
            service_name = elem.text
            if service_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_services (host_id, service_name, status, startup_type)
                    VALUES (?, ?, 'unknown', 'unknown')
                    """, (host_id, service_name.strip()))
                    services_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento servizio {service_name}: {e}")

        # Commit delle modifiche
        self.db.commit()
        self.logger.info(f"Importati {services_parsed} servizi per host {host_id}")
        return services_parsed

    def _parse_processes(self, script_element: ET.Element, host_id: int) -> int:
        """Parse dei processi attivi da SNMP"""
        processes_parsed = 0

        # Parsing dalle tabelle (struttura più dettagliata)
        for table in script_element.findall('table'):
            pid = table.get('key')
            process_name = None
            process_path = None

            for elem in table.findall('elem'):
                if elem.get('key') == 'Name':
                    process_name = elem.text
                elif elem.get('key') == 'Path':
                    process_path = elem.text

            if pid and process_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_processes 
                    (host_id, process_id, process_name, process_path, memory_usage)
                    VALUES (?, ?, ?, ?, NULL)
                    """, (host_id, int(pid), process_name, process_path))
                    processes_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento processo {process_name}: {e}")

        # Parsing alternativo dai semplici <elem> se non ci sono tabelle
        if processes_parsed == 0:
            for elem in script_element.findall('elem'):
                process_name = elem.text
                if process_name:
                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_processes 
                        (host_id, process_id, process_name, process_path, memory_usage)
                        VALUES (?, NULL, ?, NULL, NULL)
                        """, (host_id, process_name.strip()))
                        processes_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento processo {process_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {processes_parsed} processi per host {host_id}")
        return processes_parsed

    def _parse_win32_software(self, script_element: ET.Element, host_id: int) -> int:
        """Parse del software installato da SNMP"""
        software_parsed = 0
        script_output = script_element.get('output', '')

        # Parsing dal testo di output (formato: "Nome Software; Data")
        lines = script_output.split('\n')
        for line in lines:
            line = line.strip()
            if ';' in line:
                parts = line.split(';')
                if len(parts) >= 2:
                    software_name = parts[0].strip()
                    install_date = parts[1].strip()

                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_software 
                        (host_id, software_name, version, install_date, vendor)
                        VALUES (?, ?, NULL, ?, NULL)
                        """, (host_id, software_name, install_date))
                        software_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento software {software_name}: {e}")

        # Parsing alternativo dalle tabelle strutturate
        for table in script_element.findall('table'):
            software_name = None
            install_date = None

            for elem in table.findall('elem'):
                if elem.get('key') == 'name':
                    software_name = elem.text
                elif elem.get('key') == 'install_date':
                    install_date = elem.text

            if software_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_software 
                    (host_id, software_name, version, install_date, vendor)
                    VALUES (?, ?, NULL, ?, NULL)
                    """, (host_id, software_name, install_date))
                    software_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento software {software_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {software_parsed} software per host {host_id}")
        return software_parsed

    def _parse_win32_users(self, script_element: ET.Element, host_id: int) -> int:
        """Parse degli utenti Windows da SNMP"""
        users_parsed = 0

        for elem in script_element.findall('elem'):
            username = elem.text
            if username:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_users 
                    (host_id, username, full_name, description, status)
                    VALUES (?, ?, NULL, NULL, 'unknown')
                    """, (host_id, username.strip()))
                    users_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento utente {username}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {users_parsed} utenti per host {host_id}")
        return users_parsed

    def _parse_interfaces(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle interfacce di rete da SNMP"""
        interfaces_parsed = 0
        script_output = script_element.get('output', '')

        # Parsing dal testo di output
        current_interface = {}
        lines = script_output.split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                if current_interface.get('name'):
                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_interfaces 
                        (host_id, interface_name, ip_address, netmask, interface_type, status)
                        VALUES (?, ?, ?, ?, ?, 'unknown')
                        """, (
                            host_id,
                            current_interface.get('name'),
                            current_interface.get('ip_address'),
                            current_interface.get('netmask'),
                            current_interface.get('type')
                        ))
                        interfaces_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento interfaccia: {e}")
                current_interface = {}
                continue

            if 'IP address:' in line:
                parts = line.split('IP address:')
                if len(parts) > 1:
                    ip_info = parts[1].strip()
                    if 'Netmask:' in ip_info:
                        ip_parts = ip_info.split('Netmask:')
                        current_interface['ip_address'] = ip_parts[0].strip()
                        current_interface['netmask'] = ip_parts[1].strip()
            elif 'Type:' in line:
                parts = line.split('Type:')
                if len(parts) > 1:
                    current_interface['type'] = parts[1].strip()
            elif not current_interface.get('name'):
                # Prima riga probabilmente è il nome dell'interfaccia
                current_interface['name'] = line

        # Gestisci l'ultima interfaccia se presente
        if current_interface.get('name'):
            try:
                self.db.execute("""
                INSERT OR IGNORE INTO snmp_interfaces 
                (host_id, interface_name, ip_address, netmask, interface_type, status)
                VALUES (?, ?, ?, ?, ?, 'unknown')
                """, (
                    host_id,
                    current_interface.get('name'),
                    current_interface.get('ip_address'),
                    current_interface.get('netmask'),
                    current_interface.get('type')
                ))
                interfaces_parsed += 1
            except Exception as e:
                self.logger.error(f"Errore inserimento interfaccia: {e}")

        self.db.commit()
        self.logger.info(f"Importate {interfaces_parsed} interfacce per host {host_id}")
        return interfaces_parsed

    def _parse_netstat(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle connessioni di rete da SNMP"""
        connections_parsed = 0
        script_output = script_element.get('output', '')

        lines = script_output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith(('TCP ', 'UDP ')):
                parts = line.split()
                if len(parts) >= 3:
                    protocol = parts[0]
                    local_address = parts[1]
                    remote_address = parts[2] if len(parts) > 2 else '0.0.0.0:0'

                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_network_connections 
                        (host_id, protocol, local_address, remote_address, state)
                        VALUES (?, ?, ?, ?, 'unknown')
                        """, (host_id, protocol, local_address, remote_address))
                        connections_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento connessione: {e}")

        self.db.commit()
        self.logger.info(f"Importate {connections_parsed} connessioni per host {host_id}")
        return connections_parsed

    def _parse_system_description(self, script_element: ET.Element, host_id: int) -> int:
        """Parse della descrizione del sistema da SNMP"""
        script_output = script_element.get('output', '')

        # Estrai informazioni dalla descrizione del sistema
        hardware_info = None
        software_info = None
        uptime = None

        lines = script_output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('Hardware:'):
                hardware_info = line.replace('Hardware:', '').strip()
            elif 'Software:' in line:
                software_info = line.split('Software:')[1].strip()
            elif 'System uptime:' in line:
                uptime = line.replace('System uptime:', '').strip()

        try:
            self.db.execute("""
            INSERT OR REPLACE INTO snmp_system_info 
            (host_id, hardware_info, software_info, system_uptime, contact, location)
            VALUES (?, ?, ?, ?, NULL, NULL)
            """, (host_id, hardware_info, software_info, uptime))

            self.db.commit()
            self.logger.info(f"Importate informazioni di sistema per host {host_id}")
            return 1
        except Exception as e:
            self.logger.error(f"Errore inserimento info di sistema: {e}")
            return 0

    def _parse_win32_shares(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle condivisioni Windows da SNMP"""
        shares_parsed = 0

        # Parse da elementi strutturati
        for elem in script_element.findall('elem'):
            share_name = elem.get('key')
            share_path = elem.text

            if share_name and share_path:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_shares 
                    (host_id, share_name, share_path, description)
                    VALUES (?, ?, ?, NULL)
                    """, (host_id, share_name, share_path))
                    shares_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento condivisione {share_name}: {e}")

        # Parse alternativo dal testo di output
        if shares_parsed == 0:
            script_output = script_element.get('output', '')
            lines = script_output.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        share_name = parts[0].strip()
                        share_path = parts[1].strip()

                        try:
                            self.db.execute("""
                            INSERT OR IGNORE INTO snmp_shares 
                            (host_id, share_name, share_path, description)
                            VALUES (?, ?, ?, NULL)
                            """, (host_id, share_name, share_path))
                            shares_parsed += 1
                        except Exception as e:
                            self.logger.error(f"Errore inserimento condivisione {share_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importate {shares_parsed} condivisioni per host {host_id}")
        return shares_parsed


"""
Advanced Nmap XML Parser - Versione Completa e Corretta
Extended parser with SNMP and specialized script handling
"""

import sys
import os
import logging
import sqlite3
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import re

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from nmap_xml_parser import NmapXMLParser
except ImportError:
    print("Warning: Could not import NmapXMLParser, using standalone mode")
    NmapXMLParser = object


class FixedSNMPParser:
    """Parser corretto per i dati SNMP da file XML Nmap"""

    def __init__(self, db_connection):
        self.db = db_connection
        self.logger = logging.getLogger(__name__)

    def parse_snmp_script(self, script_element: ET.Element, port_id: int, host_id: int):
        """Parse specifico per script SNMP basato sul tipo"""
        script_id = script_element.get('id', '')

        if script_id == 'snmp-win32-services':
            return self._parse_win32_services(script_element, host_id)
        elif script_id == 'snmp-processes':
            return self._parse_processes(script_element, host_id)
        elif script_id == 'snmp-win32-software':
            return self._parse_win32_software(script_element, host_id)
        elif script_id == 'snmp-win32-users':
            return self._parse_win32_users(script_element, host_id)
        elif script_id == 'snmp-interfaces':
            return self._parse_interfaces(script_element, host_id)
        elif script_id == 'snmp-netstat':
            return self._parse_netstat(script_element, host_id)
        elif script_id == 'snmp-sysdescr':
            return self._parse_system_description(script_element, host_id)
        elif script_id == 'snmp-win32-shares':
            return self._parse_win32_shares(script_element, host_id)

        return 0

    def _parse_win32_services(self, script_element: ET.Element, host_id: int) -> int:
        """Parse dei servizi Windows da SNMP"""
        services_parsed = 0

        # Parsing dai <elem> diretti (lista servizi)
        for elem in script_element.findall('elem'):
            service_name = elem.text
            if service_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_services (host_id, service_name, status, startup_type)
                    VALUES (?, ?, 'unknown', 'unknown')
                    """, (host_id, service_name.strip()))
                    services_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento servizio {service_name}: {e}")

        # Commit delle modifiche
        self.db.commit()
        self.logger.info(f"Importati {services_parsed} servizi per host {host_id}")
        return services_parsed

    def _parse_processes(self, script_element: ET.Element, host_id: int) -> int:
        """Parse dei processi attivi da SNMP"""
        processes_parsed = 0

        # Parsing dalle tabelle (struttura più dettagliata)
        for table in script_element.findall('table'):
            pid = table.get('key')
            process_name = None
            process_path = None

            for elem in table.findall('elem'):
                if elem.get('key') == 'Name':
                    process_name = elem.text
                elif elem.get('key') == 'Path':
                    process_path = elem.text

            if pid and process_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_processes 
                    (host_id, process_id, process_name, process_path, memory_usage)
                    VALUES (?, ?, ?, ?, NULL)
                    """, (host_id, int(pid), process_name, process_path))
                    processes_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento processo {process_name}: {e}")

        # Parsing alternativo dai semplici <elem> se non ci sono tabelle
        if processes_parsed == 0:
            for elem in script_element.findall('elem'):
                process_name = elem.text
                if process_name:
                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_processes 
                        (host_id, process_id, process_name, process_path, memory_usage)
                        VALUES (?, NULL, ?, NULL, NULL)
                        """, (host_id, process_name.strip()))
                        processes_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento processo {process_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {processes_parsed} processi per host {host_id}")
        return processes_parsed

    def _parse_win32_software(self, script_element: ET.Element, host_id: int) -> int:
        """Parse del software installato da SNMP"""
        software_parsed = 0
        script_output = script_element.get('output', '')

        # Parsing dal testo di output (formato: "Nome Software; Data")
        lines = script_output.split('\n')
        for line in lines:
            line = line.strip()
            if ';' in line:
                parts = line.split(';')
                if len(parts) >= 2:
                    software_name = parts[0].strip()
                    install_date = parts[1].strip()

                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_software 
                        (host_id, software_name, version, install_date, vendor)
                        VALUES (?, ?, NULL, ?, NULL)
                        """, (host_id, software_name, install_date))
                        software_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento software {software_name}: {e}")

        # Parsing alternativo dalle tabelle strutturate
        for table in script_element.findall('table'):
            software_name = None
            install_date = None

            for elem in table.findall('elem'):
                if elem.get('key') == 'name':
                    software_name = elem.text
                elif elem.get('key') == 'install_date':
                    install_date = elem.text

            if software_name:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_software 
                    (host_id, software_name, version, install_date, vendor)
                    VALUES (?, ?, NULL, ?, NULL)
                    """, (host_id, software_name, install_date))
                    software_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento software {software_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {software_parsed} software per host {host_id}")
        return software_parsed

    def _parse_win32_users(self, script_element: ET.Element, host_id: int) -> int:
        """Parse degli utenti Windows da SNMP"""
        users_parsed = 0

        for elem in script_element.findall('elem'):
            username = elem.text
            if username:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_users 
                    (host_id, username, full_name, description, status)
                    VALUES (?, ?, NULL, NULL, 'unknown')
                    """, (host_id, username.strip()))
                    users_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento utente {username}: {e}")

        self.db.commit()
        self.logger.info(f"Importati {users_parsed} utenti per host {host_id}")
        return users_parsed

    def _parse_interfaces(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle interfacce di rete da SNMP"""
        interfaces_parsed = 0
        script_output = script_element.get('output', '')

        # Parsing dal testo di output
        current_interface = {}
        lines = script_output.split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                if current_interface.get('name'):
                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_interfaces 
                        (host_id, interface_name, ip_address, netmask, interface_type, status)
                        VALUES (?, ?, ?, ?, ?, 'unknown')
                        """, (
                            host_id,
                            current_interface.get('name'),
                            current_interface.get('ip_address'),
                            current_interface.get('netmask'),
                            current_interface.get('type')
                        ))
                        interfaces_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento interfaccia: {e}")
                current_interface = {}
                continue

            if 'IP address:' in line:
                parts = line.split('IP address:')
                if len(parts) > 1:
                    ip_info = parts[1].strip()
                    if 'Netmask:' in ip_info:
                        ip_parts = ip_info.split('Netmask:')
                        current_interface['ip_address'] = ip_parts[0].strip()
                        current_interface['netmask'] = ip_parts[1].strip()
            elif 'Type:' in line:
                parts = line.split('Type:')
                if len(parts) > 1:
                    current_interface['type'] = parts[1].strip()
            elif not current_interface.get('name'):
                # Prima riga probabilmente è il nome dell'interfaccia
                current_interface['name'] = line

        # Gestisci l'ultima interfaccia se presente
        if current_interface.get('name'):
            try:
                self.db.execute("""
                INSERT OR IGNORE INTO snmp_interfaces 
                (host_id, interface_name, ip_address, netmask, interface_type, status)
                VALUES (?, ?, ?, ?, ?, 'unknown')
                """, (
                    host_id,
                    current_interface.get('name'),
                    current_interface.get('ip_address'),
                    current_interface.get('netmask'),
                    current_interface.get('type')
                ))
                interfaces_parsed += 1
            except Exception as e:
                self.logger.error(f"Errore inserimento interfaccia: {e}")

        self.db.commit()
        self.logger.info(f"Importate {interfaces_parsed} interfacce per host {host_id}")
        return interfaces_parsed

    def _parse_netstat(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle connessioni di rete da SNMP"""
        connections_parsed = 0
        script_output = script_element.get('output', '')

        lines = script_output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith(('TCP ', 'UDP ')):
                parts = line.split()
                if len(parts) >= 3:
                    protocol = parts[0]
                    local_address = parts[1]
                    remote_address = parts[2] if len(parts) > 2 else '0.0.0.0:0'

                    try:
                        self.db.execute("""
                        INSERT OR IGNORE INTO snmp_network_connections 
                        (host_id, protocol, local_address, remote_address, state)
                        VALUES (?, ?, ?, ?, 'unknown')
                        """, (host_id, protocol, local_address, remote_address))
                        connections_parsed += 1
                    except Exception as e:
                        self.logger.error(f"Errore inserimento connessione: {e}")

        self.db.commit()
        self.logger.info(f"Importate {connections_parsed} connessioni per host {host_id}")
        return connections_parsed

    def _parse_system_description(self, script_element: ET.Element, host_id: int) -> int:
        """Parse della descrizione del sistema da SNMP"""
        script_output = script_element.get('output', '')

        # Estrai informazioni dalla descrizione del sistema
        hardware_info = None
        software_info = None
        uptime = None

        lines = script_output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('Hardware:'):
                hardware_info = line.replace('Hardware:', '').strip()
            elif 'Software:' in line:
                software_info = line.split('Software:')[1].strip()
            elif 'System uptime:' in line:
                uptime = line.replace('System uptime:', '').strip()

        try:
            self.db.execute("""
            INSERT OR REPLACE INTO snmp_system_info 
            (host_id, hardware_info, software_info, system_uptime, contact, location)
            VALUES (?, ?, ?, ?, NULL, NULL)
            """, (host_id, hardware_info, software_info, uptime))

            self.db.commit()
            self.logger.info(f"Importate informazioni di sistema per host {host_id}")
            return 1
        except Exception as e:
            self.logger.error(f"Errore inserimento info di sistema: {e}")
            return 0

    def _parse_win32_shares(self, script_element: ET.Element, host_id: int) -> int:
        """Parse delle condivisioni Windows da SNMP"""
        shares_parsed = 0

        # Parse da elementi strutturati
        for elem in script_element.findall('elem'):
            share_name = elem.get('key')
            share_path = elem.text

            if share_name and share_path:
                try:
                    self.db.execute("""
                    INSERT OR IGNORE INTO snmp_shares 
                    (host_id, share_name, share_path, description)
                    VALUES (?, ?, ?, NULL)
                    """, (host_id, share_name, share_path))
                    shares_parsed += 1
                except Exception as e:
                    self.logger.error(f"Errore inserimento condivisione {share_name}: {e}")

        # Parse alternativo dal testo di output
        if shares_parsed == 0:
            script_output = script_element.get('output', '')
            lines = script_output.split('\n')
            for line in lines:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        share_name = parts[0].strip()
                        share_path = parts[1].strip()

                        try:
                            self.db.execute("""
                            INSERT OR IGNORE INTO snmp_shares 
                            (host_id, share_name, share_path, description)
                            VALUES (?, ?, ?, NULL)
                            """, (host_id, share_name, share_path))
                            shares_parsed += 1
                        except Exception as e:
                            self.logger.error(f"Errore inserimento condivisione {share_name}: {e}")

        self.db.commit()
        self.logger.info(f"Importate {shares_parsed} condivisioni per host {host_id}")
        return shares_parsed


class AdvancedNmapParser(NmapXMLParser):
    """Extended parser with specialized handling for different script types"""

    def __init__(self, db_path: str = "instance/nmap_scans.db"):
        if NmapXMLParser != object:
            super().__init__(db_path)
        else:
            self.db_path = db_path
            self.logger = logging.getLogger(__name__)

        self.snmp_parser = None

        # Define script handlers for different types of scripts
        self.script_handlers = {
            'snmp-processes': self._handle_snmp_script,
            'snmp-netstat': self._handle_snmp_script,
            'snmp-sysdescr': self._handle_snmp_script,
            'snmp-interfaces': self._handle_snmp_script,
            'snmp-win32-services': self._handle_snmp_script,
            'snmp-win32-software': self._handle_snmp_script,
            'snmp-win32-users': self._handle_snmp_script,
            'snmp-win32-shares': self._handle_snmp_script,
            'http-vuln-cve': self._handle_http_vuln,
            'smb-vuln': self._handle_smb_vuln,
            'ssl-cert': self._handle_ssl_cert,
            'ssh-hostkey': self._handle_ssh_hostkey,
        }

    def _get_db_connection(self):
        """Get database connection"""
        if hasattr(self, 'db') and hasattr(self.db, 'conn'):
            return self.db.conn
        else:
            return sqlite3.connect(self.db_path)

    def _parse_scripts(self, port_element, port_id: int):
        """Override to add specialized script handling"""

        # Call parent method first if available
        if hasattr(super(), '_parse_scripts'):
            super()._parse_scripts(port_element, port_id)

        # Get host_id for SNMP scripts that need it
        conn = self._get_db_connection()
        cursor = conn.execute("SELECT host_id FROM ports WHERE id = ?", (port_id,))
        result = cursor.fetchone()
        if not result:
            self.logger.error(f"Could not find host_id for port_id {port_id}")
            return

        host_id = result[0]

        # Initialize SNMP parser if needed
        if not self.snmp_parser:
            self.snmp_parser = FixedSNMPParser(conn)

        # Process each script with specialized handlers
        for script in port_element.findall('script'):
            script_name = script.get('id', '')

            # Check if we have a specialized handler
            for pattern, handler in self.script_handlers.items():
                if pattern in script_name:
                    try:
                        handler(script, port_id, host_id)
                    except Exception as e:
                        self.logger.error(f"Error in specialized handler for {script_name}: {e}")
                    break

    def _handle_snmp_script(self, script, port_id: int, host_id: int):
        """Handle SNMP scripts with specialized parser"""
        try:
            results = self.snmp_parser.parse_snmp_script(script, port_id, host_id)
            script_name = script.get('id', '')
            self.logger.info(f"Parsed {results} records from {script_name}")
            return results
        except Exception as e:
            self.logger.error(f"Error parsing SNMP script {script.get('id', '')}: {e}")
            return 0

    def _handle_http_vuln(self, script, port_id: int, host_id: int):
        """Handle HTTP vulnerability scripts"""
        script_name = script.get('id', '')
        script_output = script.get('output', '')

        # Look for CVE information in the script name or output
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, script_name + ' ' + script_output)

        if cves:
            conn = self._get_db_connection()
            for cve in set(cves):  # Remove duplicates
                try:
                    conn.execute("""
                    INSERT OR IGNORE INTO vulnerabilities 
                    (host_id, port_id, vuln_id, title, description, severity)
                    VALUES (?, ?, ?, ?, ?, 'unknown')
                    """, (host_id, port_id, cve, f"HTTP Vulnerability {cve}", script_output))
                except Exception as e:
                    self.logger.error(f"Error storing vulnerability {cve}: {e}")

            conn.commit()
            self.logger.info(f"Stored {len(cves)} vulnerabilities from {script_name}")

    def _handle_smb_vuln(self, script, port_id: int, host_id: int):
        """Handle SMB vulnerability scripts"""
        # Similar to HTTP vuln handler but for SMB
        self._handle_http_vuln(script, port_id, host_id)

    def _handle_ssl_cert(self, script, port_id: int, host_id: int):
        """Handle SSL certificate information"""
        script_output = script.get('output', '')

        # Extract certificate information
        cert_info = self._parse_ssl_certificate(script_output)

        conn = self._get_db_connection()
        try:
            conn.execute("""
            INSERT OR REPLACE INTO ssl_certificates 
            (host_id, port_id, subject, issuer, not_before, not_after, serial)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                host_id, port_id,
                cert_info.get('subject'),
                cert_info.get('issuer'),
                cert_info.get('not_before'),
                cert_info.get('not_after'),
                cert_info.get('serial')
            ))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error storing SSL certificate: {e}")

    def _parse_ssl_certificate(self, output: str) -> dict:
        """Parse SSL certificate information"""
        cert_info = {}

        # Common SSL certificate fields
        patterns = {
            'subject': r'Subject:\s*(.+?)(?:\n|$)',
            'issuer': r'Issuer:\s*(.+?)(?:\n|$)',
            'not_before': r'Not valid before:\s*(.+?)(?:\n|$)',
            'not_after': r'Not valid after:\s*(.+?)(?:\n|$)',
            'serial': r'Serial Number:\s*(.+?)(?:\n|$)',
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                cert_info[key] = match.group(1).strip()

        return cert_info

    def _handle_ssh_hostkey(self, script, port_id: int, host_id: int):
        """Handle SSH host key information"""
        script_output = script.get('output', '')

        # Parse SSH host keys
        hostkeys = self._parse_ssh_hostkeys(script_output)

        conn = self._get_db_connection()
        for key_info in hostkeys:
            try:
                conn.execute("""
                INSERT OR IGNORE INTO ssh_hostkeys 
                (host_id, port_id, key_type, key_size, fingerprint)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    host_id, port_id,
                    key_info.get('key_type'),
                    key_info.get('key_size'),
                    key_info.get('fingerprint')
                ))
            except Exception as e:
                self.logger.error(f"Error storing SSH hostkey: {e}")

        conn.commit()

    def _parse_ssh_hostkeys(self, output: str) -> list:
        """Parse SSH host key information"""
        hostkeys = []
        key_blocks = re.split(r'\n(?=\d+\s+\w+)', output)

        for block in key_blocks:
            if not block.strip():
                continue

            key_info = {}
            lines = block.strip().split('\n')

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Parse key size and type
                key_match = re.match(r'(\d+)\s+(\w+)', line)
                if key_match:
                    key_info['key_size'] = key_match.group(1)
                    key_info['key_type'] = key_match.group(2)
                    continue

                # Parse fingerprints
                if 'fingerprint' in line.lower():
                    key_info['fingerprint'] = line.split(':', 1)[1].strip()

            if key_info:
                hostkeys.append(key_info)

        return hostkeys


# Standalone functionality for testing
def test_snmp_parsing():
    """Test function per verificare il parsing SNMP"""

    print("🧪 Test del nuovo parser SNMP...")

    # Test con un file XML di esempio
    import os
    test_files = ['sei.xml', 'quattro.xml', 'due.xml']

    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"\n📁 Testing file: {test_file}")

            try:
                # Parse XML file
                tree = ET.parse(test_file)
                root = tree.getroot()

                # Find SNMP scripts
                snmp_scripts = []
                for script in root.findall('.//script'):
                    script_id = script.get('id', '')
                    if script_id.startswith('snmp-'):
                        snmp_scripts.append((script_id, script))

                print(f"  ✅ Found {len(snmp_scripts)} SNMP scripts")

                # Test parsing (without database)
                for script_id, script in snmp_scripts[:3]:  # Test primi 3
                    output_len = len(script.get('output', ''))
                    elem_count = len(script.findall('elem'))
                    table_count = len(script.findall('table'))
                    print(f"    📋 {script_id}: {output_len} chars output, {elem_count} elements, {table_count} tables")

            except Exception as e:
                print(f"  ❌ Error testing {test_file}: {e}")
        else:
            print(f"  ⚠️  File not found: {test_file}")


if __name__ == "__main__":
    test_snmp_parsing()