#!/usr/bin/env python3
"""
Software Parser - Gestisce il parsing di software installato e processi in esecuzione
"""

import xml.etree.ElementTree as ET
import re
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class SoftwareParser:
    """Parser specializzato per software e processi da script NSE"""

    def __init__(self, database_manager):
        """Inizializza il parser con riferimento al database manager"""
        self.db = database_manager

    def parse_software_and_processes(self, xml_file_path: str):
        """Parse software installato e processi in esecuzione da file XML"""
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            for host in root.findall('host'):
                ip_addr = self._get_host_ip(host)
                if not ip_addr:
                    continue

                # Parse software e processi da tutti gli script
                self._parse_host_software_and_processes(host, ip_addr)

            self.db.commit()
            logger.info(f"Completato parsing software e processi da {xml_file_path}")

        except Exception as e:
            logger.error(f"Errore nel parsing software/processi da {xml_file_path}: {e}")

    def _get_host_ip(self, host) -> Optional[str]:
        """Estrae l'IP dell'host"""
        for address in host.findall('address'):
            if address.get('addrtype') == 'ipv4':
                return address.get('addr')
        return None

    def _parse_host_software_and_processes(self, host, ip_addr: str):
        """Parse software e processi per un singolo host"""
        # Parse da script NSE
        for script in host.findall('.//script'):
            script_name = script.get('id', '')
            output = script.get('output', '')

            if not output:
                continue

            # Determina il tipo di script e parse di conseguenza
            if self._is_software_script(script_name):
                self._parse_software_from_script(ip_addr, script_name, output)

            if self._is_process_script(script_name):
                self._parse_processes_from_script(ip_addr, script_name, output)

    def _is_software_script(self, script_name: str) -> bool:
        """Determina se lo script contiene informazioni sui software"""
        software_keywords = [
            'smb-enum-software', 'smb-software', 'wmi-enum-software',
            'installed', 'software', 'enum-software'
        ]
        return any(keyword in script_name.lower() for keyword in software_keywords)

    def _is_process_script(self, script_name: str) -> bool:
        """Determina se lo script contiene informazioni sui processi"""
        process_keywords = [
            'smb-enum-processes', 'smb-processes', 'wmi-enum-processes',
            'processes', 'enum-processes', 'ps-exec'
        ]
        return any(keyword in script_name.lower() for keyword in process_keywords)

    def _parse_software_from_script(self, ip_addr: str, script_name: str, output: str):
        """Parse software installato da output di script NSE"""
        try:
            if 'smb-enum-software' in script_name or 'wmi-enum-software' in script_name:
                self._parse_smb_software(ip_addr, output)
            else:
                self._parse_generic_software(ip_addr, output)

        except Exception as e:
            logger.warning(f"Errore parsing software da script {script_name}: {e}")

    def _parse_smb_software(self, ip_addr: str, output: str):
        """Parse software da output SMB/WMI"""
        try:
            # Pattern per software con data di installazione
            # Cerca pattern come "Software Name; YYYY-MM-DDTHH:MM:SS"
            pattern = r'([^;]+);\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
            matches = re.findall(pattern, output)

            for software_name, install_date_str in matches:
                software_name = software_name.strip()

                # Skip se è troppo corto o generico
                if len(software_name) < 3 or software_name.lower() in ['', 'null', 'none']:
                    continue

                try:
                    install_date = datetime.fromisoformat(install_date_str)
                except:
                    install_date = None

                # Estrai versione se presente nel nome
                version = self._extract_version_from_name(software_name)

                software_data = {
                    'ip_address': ip_addr,
                    'software_name': software_name,
                    'install_date': install_date,
                    'version': version,
                    'publisher': None
                }

                self.db.insert_software(software_data)

            # Se non trova pattern specifici, prova parsing alternativo
            if not matches:
                self._parse_alternative_software_format(ip_addr, output)

        except Exception as e:
            logger.warning(f"Errore parsing SMB software per {ip_addr}: {e}")

    def _parse_alternative_software_format(self, ip_addr: str, output: str):
        """Parse software con formato alternativo"""
        try:
            # Cerca liste di software separati da newline
            lines = output.split('\n')

            for line in lines:
                line = line.strip()

                # Skip linee vuote o troppo corte
                if len(line) < 5:
                    continue

                # Skip linee che sembrano header o separatori
                if any(char in line for char in ['===', '---', '***']):
                    continue

                # Cerca pattern di software validi
                if self._is_valid_software_name(line):
                    version = self._extract_version_from_name(line)

                    software_data = {
                        'ip_address': ip_addr,
                        'software_name': line,
                        'install_date': None,
                        'version': version,
                        'publisher': None
                    }

                    self.db.insert_software(software_data)

        except Exception as e:
            logger.warning(f"Errore parsing software alternativo per {ip_addr}: {e}")

    def _parse_generic_software(self, ip_addr: str, output: str):
        """Parse generico per software"""
        try:
            # Cerca pattern generici di software
            patterns = [
                r'(\w+(?:\s+\w+)*)\s+v?(\d+\.\d+(?:\.\d+)*)',  # Nome Version
                r'([A-Z][a-zA-Z0-9\s]+(?:Edition|Suite|Pro|Standard)?)',  # Nomi software tipici
            ]

            for pattern in patterns:
                matches = re.findall(pattern, output, re.IGNORECASE)

                for match in matches:
                    if isinstance(match, tuple):
                        software_name = match[0].strip()
                        version = match[1] if len(match) > 1 else None
                    else:
                        software_name = match.strip()
                        version = None

                    if self._is_valid_software_name(software_name):
                        software_data = {
                            'ip_address': ip_addr,
                            'software_name': software_name,
                            'install_date': None,
                            'version': version,
                            'publisher': None
                        }

                        self.db.insert_software(software_data)

        except Exception as e:
            logger.warning(f"Errore parsing software generico per {ip_addr}: {e}")

    def _parse_processes_from_script(self, ip_addr: str, script_name: str, output: str):
        """Parse processi in esecuzione da output di script NSE"""
        try:
            if 'smb-enum-processes' in script_name or 'wmi-enum-processes' in script_name:
                self._parse_smb_processes(ip_addr, output)
            else:
                self._parse_generic_processes(ip_addr, output)

        except Exception as e:
            logger.warning(f"Errore parsing processi da script {script_name}: {e}")

    def _parse_smb_processes(self, ip_addr: str, output: str):
        """Parse processi da output SMB/WMI"""
        try:
            # Pattern per processi con PID
            # Cerca pattern come "PID: 1234, Nome: process.exe, Path: C:\path\"
            pid_pattern = r'(?:PID|pid):\s*(\d+).*?(?:Nome|Name):\s*([^\s,]+)(?:.*?(?:Path|path):\s*([^,\n]+))?'
            matches = re.findall(pid_pattern, output, re.IGNORECASE | re.DOTALL)

            for pid_str, process_name, process_path in matches:
                try:
                    pid = int(pid_str)
                    process_name = process_name.strip()
                    process_path = process_path.strip() if process_path else None

                    if self._is_valid_process_name(process_name):
                        process_data = {
                            'ip_address': ip_addr,
                            'pid': pid,
                            'process_name': process_name,
                            'process_path': process_path,
                            'process_params': None
                        }

                        self.db.insert_process(process_data)

                except ValueError:
                    continue

            # Se non trova pattern specifici, prova parsing alternativo
            if not matches:
                self._parse_alternative_process_format(ip_addr, output)

        except Exception as e:
            logger.warning(f"Errore parsing SMB processi per {ip_addr}: {e}")

    def _parse_alternative_process_format(self, ip_addr: str, output: str):
        """Parse processi con formato alternativo"""
        try:
            # Cerca righe che contengono .exe
            exe_pattern = r'(\d+).*?([a-zA-Z0-9_\-\.]+\.exe)(?:.*?([C-Z]:\\[^,\n]+))?'
            matches = re.findall(exe_pattern, output, re.IGNORECASE)

            for pid_str, process_name, process_path in matches:
                try:
                    pid = int(pid_str) if pid_str.isdigit() else None
                    process_name = process_name.strip()
                    process_path = process_path.strip() if process_path else None

                    if self._is_valid_process_name(process_name):
                        process_data = {
                            'ip_address': ip_addr,
                            'pid': pid,
                            'process_name': process_name,
                            'process_path': process_path,
                            'process_params': None
                        }

                        self.db.insert_process(process_data)

                except (ValueError, AttributeError):
                    continue

        except Exception as e:
            logger.warning(f"Errore parsing processi alternativo per {ip_addr}: {e}")

    def _parse_generic_processes(self, ip_addr: str, output: str):
        """Parse generico per processi"""
        try:
            # Cerca pattern generici di processi
            lines = output.split('\n')

            for line in lines:
                line = line.strip()

                # Cerca .exe o altri pattern di processi
                if '.exe' in line.lower() or self._looks_like_process_line(line):
                    # Estrai nome processo
                    process_match = re.search(r'([a-zA-Z0-9_\-\.]+\.exe)', line, re.IGNORECASE)
                    if process_match:
                        process_name = process_match.group(1)

                        # Cerca PID
                        pid_match = re.search(r'(\d{1,6})', line)
                        pid = int(pid_match.group(1)) if pid_match else None

                        if self._is_valid_process_name(process_name):
                            process_data = {
                                'ip_address': ip_addr,
                                'pid': pid,
                                'process_name': process_name,
                                'process_path': None,
                                'process_params': None
                            }

                            self.db.insert_process(process_data)

        except Exception as e:
            logger.warning(f"Errore parsing processi generico per {ip_addr}: {e}")

    def _extract_version_from_name(self, software_name: str) -> Optional[str]:
        """Estrae versione dal nome del software"""
        # Pattern per versioni comuni
        version_patterns = [
            r'(\d+\.\d+(?:\.\d+)*(?:\.\d+)*)',  # x.y.z.w
            r'v(\d+\.\d+)',  # v1.2
            r'(\d{4})',  # Anno come versione
        ]

        for pattern in version_patterns:
            match = re.search(pattern, software_name)
            if match:
                return match.group(1)

        return None

    def _is_valid_software_name(self, name: str) -> bool:
        """Verifica se è un nome software valido"""
        if len(name) < 3:
            return False

        # Skip nomi troppo generici
        invalid_names = {
            'null', 'none', 'unknown', 'n/a', 'na', 'error',
            'update', 'hotfix', 'patch', 'kb', 'microsoft'
        }

        name_lower = name.lower()
        if name_lower in invalid_names:
            return False

        # Deve contenere almeno una lettera
        if not re.search(r'[a-zA-Z]', name):
            return False

        return True

    def _is_valid_process_name(self, name: str) -> bool:
        """Verifica se è un nome processo valido"""
        if len(name) < 3:
            return False

        # Deve essere un eseguibile o processo riconoscibile
        if name.endswith('.exe') or any(char.isalnum() for char in name):
            return True

        return False

    def _looks_like_process_line(self, line: str) -> bool:
        """Determina se una riga sembra contenere informazioni sui processi"""
        process_indicators = [
            'pid', 'process', 'running', 'executable', 'service',
            'daemon', 'task', 'application'
        ]

        line_lower = line.lower()
        return any(indicator in line_lower for indicator in process_indicators)

    def debug_available_scripts(self, xml_file_path: str) -> set:
        """Debug: mostra tutti gli script disponibili"""
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            scripts_found = set()

            for script in root.findall('.//script'):
                script_name = script.get('id', '')
                if script_name:
                    scripts_found.add(script_name)

            logger.info(f"Script trovati in {xml_file_path}:")
            for script in sorted(scripts_found):
                logger.info(f"  - {script}")

            return scripts_found

        except Exception as e:
            logger.error(f"Errore debug script in {xml_file_path}: {e}")
            return set()

    def test_software_parsing(self, xml_directory: str = "../xml"):
        """Test rapido per verificare il parsing del software"""
        try:
            import os

            # Debug: stampa tutti gli script disponibili
            xml_files = [f for f in os.listdir(xml_directory) if f.endswith('.xml')]
            all_scripts = set()

            for xml_file in xml_files:
                file_path = os.path.join(xml_directory, xml_file)
                scripts = self.debug_available_scripts(file_path)
                all_scripts.update(scripts)

            print(f"\nTutti gli script NSE trovati ({len(all_scripts)}):")
            for script in sorted(all_scripts):
                print(f"  - {script}")

            # Cerca specificamente script di software
            software_scripts = [s for s in all_scripts if any(keyword in s.lower()
                                                              for keyword in
                                                              ['software', 'enum', 'installed', 'wmi', 'smb'])]

            print(f"\nScript potenzialmente legati al software ({len(software_scripts)}):")
            for script in sorted(software_scripts):
                print(f"  - {script}")

            # Test parsing su un file specifico
            if xml_files:
                test_file = os.path.join(xml_directory, xml_files[0])
                print(f"\nTestando parsing su: {test_file}")
                self.parse_software_and_processes(test_file)

                # Verifica risultati
                self.db.cursor.execute('SELECT COUNT(*) FROM installed_software')
                software_count = self.db.cursor.fetchone()[0]

                self.db.cursor.execute('SELECT COUNT(*) FROM running_processes')
                processes_count = self.db.cursor.fetchone()[0]

                print(f"Software trovati: {software_count}")
                print(f"Processi trovati: {processes_count}")

                if software_count > 0:
                    self.db.cursor.execute('SELECT software_name, install_date FROM installed_software LIMIT 5')
                    samples = self.db.cursor.fetchall()
                    print("Esempi software:")
                    for name, date in samples:
                        print(f"  - {name} ({date})")

        except Exception as e:
            logger.error(f"Errore nel test software parsing: {e}")