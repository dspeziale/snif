"""
Parser robusto e completo per file XML di NMAP
Supporta tutti i tipi di scansioni: discovery, port scan, OS detection, service detection, vulnerability scanning
"""
import xml.etree.ElementTree as ET
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import logging
from urllib.parse import unquote

logger = logging.getLogger(__name__)


class NmapXMLParser:
    def __init__(self):
        self.reset()

    def reset(self):
        """Reset del parser per una nuova scansione"""
        self.scan_info = {}
        self.hosts = []
        self.prescript_results = []
        self.postscript_results = []
        self.scan_stats = {}

    def parse_file(self, xml_file_path: str) -> Dict[str, Any]:
        """Parsa un file XML di NMAP"""
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()
            return self.parse_xml_root(root)
        except ET.ParseError as e:
            logger.error(f"Errore parsing XML file {xml_file_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Errore generico parsing file {xml_file_path}: {e}")
            raise

    def parse_xml_string(self, xml_content: str) -> Dict[str, Any]:
        """Parsa una stringa XML di NMAP"""
        try:
            root = ET.fromstring(xml_content)
            return self.parse_xml_root(root)
        except ET.ParseError as e:
            logger.error(f"Errore parsing XML string: {e}")
            raise
        except Exception as e:
            logger.error(f"Errore generico parsing XML string: {e}")
            raise

    def parse_xml_root(self, root: ET.Element) -> Dict[str, Any]:
        """Parsa l'elemento root del XML NMAP"""
        self.reset()

        if root.tag != 'nmaprun':
            raise ValueError("Il file XML non è un output valido di NMAP")

        # Informazioni sulla scansione
        self.scan_info = self._parse_scan_info(root)

        # Risultati pre-script
        self.prescript_results = self._parse_prescript(root)

        # Host discovery e analisi
        self.hosts = self._parse_hosts(root)

        # Risultati post-script
        self.postscript_results = self._parse_postscript(root)

        # Statistiche finali
        self.scan_stats = self._parse_runstats(root)

        return {
            'scan_info': self.scan_info,
            'hosts': self.hosts,
            'prescript_results': self.prescript_results,
            'postscript_results': self.postscript_results,
            'scan_stats': self.scan_stats,
            'total_hosts': len(self.hosts)
        }

    def _parse_scan_info(self, root: ET.Element) -> Dict[str, Any]:
        """Parsa le informazioni generali della scansione"""
        scan_info = {
            'scanner': root.get('scanner', 'nmap'),
            'version': root.get('version'),
            'args': root.get('args'),
            'start': root.get('start'),
            'startstr': root.get('startstr'),
            'xmloutputversion': root.get('xmloutputversion')
        }

        # Parse scaninfo element
        scaninfo_elem = root.find('scaninfo')
        if scaninfo_elem is not None:
            scan_info.update({
                'type': scaninfo_elem.get('type'),
                'protocol': scaninfo_elem.get('protocol'),
                'numservices': scaninfo_elem.get('numservices'),
                'services': scaninfo_elem.get('services')
            })

        # Parse verbose and debugging levels
        verbose_elem = root.find('verbose')
        if verbose_elem is not None:
            scan_info['verbose_level'] = verbose_elem.get('level')

        debugging_elem = root.find('debugging')
        if debugging_elem is not None:
            scan_info['debugging_level'] = debugging_elem.get('level')

        return scan_info

    def _parse_prescript(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Parsa i risultati dei pre-script"""
        results = []
        prescript_elem = root.find('prescript')
        if prescript_elem is not None:
            for script in prescript_elem.findall('script'):
                script_data = self._parse_script_element(script)
                results.append(script_data)
        return results

    def _parse_postscript(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Parsa i risultati dei post-script"""
        results = []
        postscript_elem = root.find('postscript')
        if postscript_elem is not None:
            for script in postscript_elem.findall('script'):
                script_data = self._parse_script_element(script)
                results.append(script_data)
        return results

    def _parse_hosts(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Parsa tutti gli host trovati nella scansione"""
        hosts = []

        # Parse hosthint (se presente)
        hosthint = root.find('hosthint')
        if hosthint is not None:
            hint_data = self._parse_host_element(hosthint, is_hint=True)
            if hint_data:
                hosts.append(hint_data)

        # Parse host elements
        for host_elem in root.findall('host'):
            host_data = self._parse_host_element(host_elem)
            if host_data:
                hosts.append(host_data)

        return hosts

    def _parse_host_element(self, host_elem: ET.Element, is_hint: bool = False) -> Optional[Dict[str, Any]]:
        """Parsa un singolo elemento host"""
        host_data = {
            'is_hint': is_hint,
            'starttime': host_elem.get('starttime'),
            'endtime': host_elem.get('endtime')
        }

        # Status
        status_elem = host_elem.find('status')
        if status_elem is not None:
            host_data['status'] = {
                'state': status_elem.get('state'),
                'reason': status_elem.get('reason'),
                'reason_ttl': status_elem.get('reason_ttl')
            }

        # Addresses
        host_data['addresses'] = []
        for addr_elem in host_elem.findall('address'):
            addr_data = {
                'addr': addr_elem.get('addr'),
                'addrtype': addr_elem.get('addrtype'),
                'vendor': addr_elem.get('vendor')
            }
            host_data['addresses'].append(addr_data)

        # Hostnames
        host_data['hostnames'] = []
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            for hostname_elem in hostnames_elem.findall('hostname'):
                hostname_data = {
                    'name': hostname_elem.get('name'),
                    'type': hostname_elem.get('type')
                }
                host_data['hostnames'].append(hostname_data)

        # Ports
        host_data['ports'] = []
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            # Extra ports
            extraports_elem = ports_elem.find('extraports')
            if extraports_elem is not None:
                host_data['extraports'] = {
                    'state': extraports_elem.get('state'),
                    'count': extraports_elem.get('count')
                }

                extrareasons_elem = extraports_elem.find('extrareasons')
                if extrareasons_elem is not None:
                    host_data['extraports']['reasons'] = {
                        'reason': extrareasons_elem.get('reason'),
                        'count': extrareasons_elem.get('count'),
                        'proto': extrareasons_elem.get('proto'),
                        'ports': extrareasons_elem.get('ports')
                    }

            # Individual ports
            for port_elem in ports_elem.findall('port'):
                port_data = self._parse_port_element(port_elem)
                host_data['ports'].append(port_data)

        # OS Detection
        host_data['os'] = []
        os_elem = host_elem.find('os')
        if os_elem is not None:
            # Ports used for OS detection
            portused_elems = os_elem.findall('portused')
            os_portused = []
            for portused_elem in portused_elems:
                os_portused.append({
                    'state': portused_elem.get('state'),
                    'proto': portused_elem.get('proto'),
                    'portid': portused_elem.get('portid')
                })

            # OS matches
            for osmatch_elem in os_elem.findall('osmatch'):
                osmatch_data = {
                    'name': osmatch_elem.get('name'),
                    'accuracy': osmatch_elem.get('accuracy'),
                    'line': osmatch_elem.get('line'),
                    'portused': os_portused
                }

                # OS classes
                osmatch_data['osclasses'] = []
                for osclass_elem in osmatch_elem.findall('osclass'):
                    osclass_data = {
                        'type': osclass_elem.get('type'),
                        'vendor': osclass_elem.get('vendor'),
                        'osfamily': osclass_elem.get('osfamily'),
                        'osgen': osclass_elem.get('osgen'),
                        'accuracy': osclass_elem.get('accuracy')
                    }

                    # CPE entries
                    osclass_data['cpes'] = []
                    for cpe_elem in osclass_elem.findall('cpe'):
                        osclass_data['cpes'].append(cpe_elem.text)

                    osmatch_data['osclasses'].append(osclass_data)

                host_data['os'].append(osmatch_data)

        # Distance
        distance_elem = host_elem.find('distance')
        if distance_elem is not None:
            host_data['distance'] = distance_elem.get('value')

        # TCP sequence prediction
        tcpseq_elem = host_elem.find('tcpsequence')
        if tcpseq_elem is not None:
            host_data['tcpsequence'] = {
                'index': tcpseq_elem.get('index'),
                'difficulty': tcpseq_elem.get('difficulty'),
                'values': tcpseq_elem.get('values')
            }

        # IP ID sequence prediction
        ipidseq_elem = host_elem.find('ipidsequence')
        if ipidseq_elem is not None:
            host_data['ipidsequence'] = {
                'class': ipidseq_elem.get('class'),
                'values': ipidseq_elem.get('values')
            }

        # TCP timestamp sequence prediction
        tcptsseq_elem = host_elem.find('tcptssequence')
        if tcptsseq_elem is not None:
            host_data['tcptssequence'] = {
                'class': tcptsseq_elem.get('class')
            }

        # Timing stats
        times_elem = host_elem.find('times')
        if times_elem is not None:
            host_data['times'] = {
                'srtt': times_elem.get('srtt'),
                'rttvar': times_elem.get('rttvar'),
                'to': times_elem.get('to')
            }

        # Host scripts
        host_data['hostscripts'] = []
        hostscript_elem = host_elem.find('hostscript')
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall('script'):
                script_data = self._parse_script_element(script_elem)
                host_data['hostscripts'].append(script_data)

        # Trace (se presente)
        trace_elem = host_elem.find('trace')
        if trace_elem is not None:
            host_data['trace'] = self._parse_trace_element(trace_elem)

        return host_data

    def _parse_port_element(self, port_elem: ET.Element) -> Dict[str, Any]:
        """Parsa un elemento port"""
        port_data = {
            'protocol': port_elem.get('protocol'),
            'portid': int(port_elem.get('portid'))
        }

        # State
        state_elem = port_elem.find('state')
        if state_elem is not None:
            port_data['state'] = {
                'state': state_elem.get('state'),
                'reason': state_elem.get('reason'),
                'reason_ttl': state_elem.get('reason_ttl')
            }

        # Service
        service_elem = port_elem.find('service')
        if service_elem is not None:
            port_data['service'] = {
                'name': service_elem.get('name'),
                'product': service_elem.get('product'),
                'version': service_elem.get('version'),
                'extrainfo': service_elem.get('extrainfo'),
                'ostype': service_elem.get('ostype'),
                'method': service_elem.get('method'),
                'conf': service_elem.get('conf'),
                'servicefp': service_elem.get('servicefp')
            }

            # CPE entries for service
            port_data['service']['cpes'] = []
            for cpe_elem in service_elem.findall('cpe'):
                port_data['service']['cpes'].append(cpe_elem.text)

        # Scripts on this port
        port_data['scripts'] = []
        for script_elem in port_elem.findall('script'):
            script_data = self._parse_script_element(script_elem)
            port_data['scripts'].append(script_data)

        return port_data

    def _parse_script_element(self, script_elem: ET.Element) -> Dict[str, Any]:
        """Parsa un elemento script NSE"""
        script_data = {
            'id': script_elem.get('id'),
            'output': script_elem.get('output')
        }

        # Parse structured data (tables/elements)
        script_data['data'] = self._parse_script_data(script_elem)

        # Decode HTML entities nel output
        if script_data['output']:
            script_data['output'] = unquote(script_data['output'])

        return script_data

    def _parse_script_data(self, script_elem: ET.Element) -> List[Any]:
        """Parsa i dati strutturati di uno script NSE"""
        data = []

        # Parse tables
        for table_elem in script_elem.findall('table'):
            table_data = self._parse_table_element(table_elem)
            data.append(table_data)

        # Parse elements
        for elem in script_elem.findall('elem'):
            elem_data = {
                'key': elem.get('key'),
                'value': elem.text
            }
            data.append(elem_data)

        return data

    def _parse_table_element(self, table_elem: ET.Element) -> Dict[str, Any]:
        """Parsa un elemento table in uno script NSE"""
        table_data = {
            'key': table_elem.get('key'),
            'elements': {},
            'tables': []
        }

        # Parse nested elements
        for elem in table_elem.findall('elem'):
            key = elem.get('key')
            value = elem.text
            table_data['elements'][key] = value

        # Parse nested tables
        for nested_table in table_elem.findall('table'):
            nested_data = self._parse_table_element(nested_table)
            table_data['tables'].append(nested_data)

        return table_data

    def _parse_trace_element(self, trace_elem: ET.Element) -> Dict[str, Any]:
        """Parsa un elemento trace (traceroute)"""
        trace_data = {
            'proto': trace_elem.get('proto'),
            'port': trace_elem.get('port'),
            'hops': []
        }

        for hop_elem in trace_elem.findall('hop'):
            hop_data = {
                'ttl': hop_elem.get('ttl'),
                'rtt': hop_elem.get('rtt'),
                'ipaddr': hop_elem.get('ipaddr'),
                'host': hop_elem.get('host')
            }
            trace_data['hops'].append(hop_data)

        return trace_data

    def _parse_runstats(self, root: ET.Element) -> Dict[str, Any]:
        """Parsa le statistiche finali della scansione"""
        stats = {}

        runstats_elem = root.find('runstats')
        if runstats_elem is not None:
            # Finished info
            finished_elem = runstats_elem.find('finished')
            if finished_elem is not None:
                stats['finished'] = {
                    'time': finished_elem.get('time'),
                    'timestr': finished_elem.get('timestr'),
                    'summary': finished_elem.get('summary'),
                    'elapsed': finished_elem.get('elapsed'),
                    'exit': finished_elem.get('exit')
                }

            # Hosts info
            hosts_elem = runstats_elem.find('hosts')
            if hosts_elem is not None:
                stats['hosts'] = {
                    'up': hosts_elem.get('up'),
                    'down': hosts_elem.get('down'),
                    'total': hosts_elem.get('total')
                }

        return stats

    def extract_vulnerabilities(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Estrae le vulnerabilità dai dati parsati"""
        vulnerabilities = []

        for host in parsed_data.get('hosts', []):
            host_vulns = self._extract_host_vulnerabilities(host)
            vulnerabilities.extend(host_vulns)

        return vulnerabilities

    def _extract_host_vulnerabilities(self, host_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Estrae le vulnerabilità da un singolo host"""
        vulnerabilities = []

        # Trova l'IP dell'host
        host_ip = None
        for addr in host_data.get('addresses', []):
            if addr.get('addrtype') == 'ipv4':
                host_ip = addr.get('addr')
                break

        if not host_ip:
            return vulnerabilities

        # Cerca vulnerabilità nei script delle porte
        for port in host_data.get('ports', []):
            port_vulns = self._extract_port_vulnerabilities(host_ip, port)
            vulnerabilities.extend(port_vulns)

        # Cerca vulnerabilità negli host script
        for script in host_data.get('hostscripts', []):
            host_vulns = self._extract_script_vulnerabilities(host_ip, None, script)
            vulnerabilities.extend(host_vulns)

        return vulnerabilities

    def _extract_port_vulnerabilities(self, host_ip: str, port_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Estrae le vulnerabilità da una porta specifica"""
        vulnerabilities = []

        port_num = port_data.get('portid')
        protocol = port_data.get('protocol')

        for script in port_data.get('scripts', []):
            port_vulns = self._extract_script_vulnerabilities(host_ip, port_data, script)
            vulnerabilities.extend(port_vulns)

        return vulnerabilities

    def _extract_script_vulnerabilities(self, host_ip: str, port_data: Optional[Dict], script_data: Dict[str, Any]) -> \
    List[Dict[str, Any]]:
        """Estrae le vulnerabilità da un script NSE"""
        vulnerabilities = []
        script_id = script_data.get('id', '')

        # Script vulners
        if script_id == 'vulners':
            vulns = self._parse_vulners_script(host_ip, port_data, script_data)
            vulnerabilities.extend(vulns)

        # Script vulnerability-based
        elif 'vuln' in script_id or 'cve' in script_id:
            vulns = self._parse_generic_vuln_script(host_ip, port_data, script_data)
            vulnerabilities.extend(vulns)

        # Altri script specifici
        elif script_id in ['ssl-ccs-injection', 'ssl-poodle', 'ssl-heartbleed', 'smb-vuln-ms17-010']:
            vulns = self._parse_specific_vuln_script(host_ip, port_data, script_data)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _parse_vulners_script(self, host_ip: str, port_data: Optional[Dict], script_data: Dict[str, Any]) -> List[
        Dict[str, Any]]:
        """Parsa il risultato dello script vulners"""
        vulnerabilities = []

        for table in script_data.get('data', []):
            if isinstance(table, dict) and 'elements' in table:
                elements = table['elements']

                vuln_data = {
                    'host_ip': host_ip,
                    'cve_id': elements.get('id'),
                    'vuln_type': elements.get('type'),
                    'cvss_score': float(elements.get('cvss', 0)) if elements.get('cvss') else None,
                    'exploit_available': elements.get('is_exploit') == 'true',
                    'detection_method': 'vulners_script',
                    'script_id': script_data.get('id')
                }

                if port_data:
                    vuln_data.update({
                        'port': port_data.get('portid'),
                        'protocol': port_data.get('protocol'),
                        'service': port_data.get('service', {}).get('name')
                    })

                vulnerabilities.append(vuln_data)

        return vulnerabilities

    def _parse_generic_vuln_script(self, host_ip: str, port_data: Optional[Dict], script_data: Dict[str, Any]) -> List[
        Dict[str, Any]]:
        """Parsa script di vulnerabilità generici"""
        vulnerabilities = []

        output = script_data.get('output', '')
        script_id = script_data.get('id', '')

        # Cerca CVE nel output
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, output)

        # Cerca CVSS scores
        cvss_pattern = r'CVSS:\s*(\d+\.?\d*)'
        cvss_matches = re.findall(cvss_pattern, output)

        for i, cve in enumerate(cves):
            vuln_data = {
                'host_ip': host_ip,
                'cve_id': cve,
                'vuln_type': 'vulnerability',
                'cvss_score': float(cvss_matches[i]) if i < len(cvss_matches) else None,
                'description': output[:500],  # Prime 500 caratteri
                'detection_method': f'nse_script_{script_id}',
                'script_id': script_id
            }

            if port_data:
                vuln_data.update({
                    'port': port_data.get('portid'),
                    'protocol': port_data.get('protocol'),
                    'service': port_data.get('service', {}).get('name')
                })

            vulnerabilities.append(vuln_data)

        return vulnerabilities

    def _parse_specific_vuln_script(self, host_ip: str, port_data: Optional[Dict], script_data: Dict[str, Any]) -> List[
        Dict[str, Any]]:
        """Parsa script di vulnerabilità specifici"""
        vulnerabilities = []

        script_id = script_data.get('id', '')
        output = script_data.get('output', '')

        # Mapping script -> CVE noti
        vuln_mapping = {
            'ssl-heartbleed': {'cve': 'CVE-2014-0160', 'cvss': 5.0, 'name': 'Heartbleed'},
            'ssl-poodle': {'cve': 'CVE-2014-3566', 'cvss': 4.3, 'name': 'POODLE'},
            'ssl-ccs-injection': {'cve': 'CVE-2014-0224', 'cvss': 6.8, 'name': 'CCS Injection'},
            'smb-vuln-ms17-010': {'cve': 'CVE-2017-0144', 'cvss': 9.3, 'name': 'EternalBlue'}
        }

        if script_id in vuln_mapping and 'VULNERABLE' in output.upper():
            vuln_info = vuln_mapping[script_id]

            vuln_data = {
                'host_ip': host_ip,
                'cve_id': vuln_info['cve'],
                'vuln_type': 'vulnerability',
                'cvss_score': vuln_info['cvss'],
                'severity': self._calculate_severity(vuln_info['cvss']),
                'description': f"{vuln_info['name']} vulnerability detected",
                'detection_method': f'nse_script_{script_id}',
                'script_id': script_id
            }

            if port_data:
                vuln_data.update({
                    'port': port_data.get('portid'),
                    'protocol': port_data.get('protocol'),
                    'service': port_data.get('service', {}).get('name')
                })

            vulnerabilities.append(vuln_data)

        return vulnerabilities

    def _calculate_severity(self, cvss_score: float) -> str:
        """Calcola la severità basata sul CVSS score"""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'

    def extract_services(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Estrae i servizi dai dati parsati"""
        services = []

        for host in parsed_data.get('hosts', []):
            host_services = self._extract_host_services(host)
            services.extend(host_services)

        return services

    def _extract_host_services(self, host_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Estrae i servizi da un singolo host"""
        services = []

        # Trova l'IP dell'host
        host_ip = None
        for addr in host_data.get('addresses', []):
            if addr.get('addrtype') == 'ipv4':
                host_ip = addr.get('addr')
                break

        if not host_ip:
            return services

        for port in host_data.get('ports', []):
            state = port.get('state', {})
            if state.get('state') == 'open':
                service_data = {
                    'host_ip': host_ip,
                    'protocol': port.get('protocol'),
                    'port': port.get('portid'),
                    'state': state.get('state'),
                    'reason': state.get('reason')
                }

                service_info = port.get('service', {})
                service_data.update({
                    'service_name': service_info.get('name'),
                    'service_product': service_info.get('product'),
                    'service_version': service_info.get('version'),
                    'service_extrainfo': service_info.get('extrainfo'),
                    'service_ostype': service_info.get('ostype'),
                    'service_method': service_info.get('method'),
                    'service_conf': service_info.get('conf'),
                    'cpe_list': service_info.get('cpes', []),
                    'banner': service_info.get('servicefp')
                })

                services.append(service_data)

        return services

    def get_summary(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Genera un riassunto dei risultati della scansione"""
        hosts = parsed_data.get('hosts', [])

        summary = {
            'total_hosts': len(hosts),
            'hosts_up': 0,
            'hosts_down': 0,
            'total_open_ports': 0,
            'unique_services': set(),
            'vulnerabilities_found': 0,
            'critical_vulns': 0,
            'high_vulns': 0,
            'os_detected': {},
            'top_ports': {},
            'scan_duration': None
        }

        for host in hosts:
            status = host.get('status', {})
            if status.get('state') == 'up':
                summary['hosts_up'] += 1
            else:
                summary['hosts_down'] += 1

            # Conta porte aperte
            for port in host.get('ports', []):
                if port.get('state', {}).get('state') == 'open':
                    summary['total_open_ports'] += 1

                    # Servizi unici
                    service = port.get('service', {})
                    if service.get('name'):
                        summary['unique_services'].add(service.get('name'))

                    # Top ports
                    port_key = f"{port.get('protocol')}/{port.get('portid')}"
                    summary['top_ports'][port_key] = summary['top_ports'].get(port_key, 0) + 1

            # OS detection
            for os_match in host.get('os', []):
                os_name = os_match.get('name')
                if os_name:
                    summary['os_detected'][os_name] = summary['os_detected'].get(os_name, 0) + 1

        # Conta vulnerabilità
        vulnerabilities = self.extract_vulnerabilities(parsed_data)
        summary['vulnerabilities_found'] = len(vulnerabilities)

        for vuln in vulnerabilities:
            cvss = vuln.get('cvss_score', 0)
            if cvss >= 9.0:
                summary['critical_vulns'] += 1
            elif cvss >= 7.0:
                summary['high_vulns'] += 1

        # Converti set in lista per JSON serialization
        summary['unique_services'] = list(summary['unique_services'])

        # Calcola durata scansione
        scan_stats = parsed_data.get('scan_stats', {})
        finished_info = scan_stats.get('finished', {})
        if finished_info.get('elapsed'):
            summary['scan_duration'] = finished_info.get('elapsed')

        return summary


class NmapResultProcessor:
    """Classe per processare e arricchire i risultati di NMAP"""

    def __init__(self, db_manager, oui_manager, device_classifier):
        self.db = db_manager
        self.oui = oui_manager
        self.classifier = device_classifier
        self.parser = NmapXMLParser()

    def process_scan_results(self, xml_content: str, scan_type: str = "unknown") -> Dict[str, Any]:
        """Processa i risultati di una scansione NMAP"""
        try:
            # Parse XML
            parsed_data = self.parser.parse_xml_string(xml_content)

            # Salva informazioni sulla scansione
            scan_info = self._create_scan_record(parsed_data, scan_type, xml_content)
            scan_id = scan_info['id']

            # Processa ogni host trovato
            processed_hosts = []
            for host_data in parsed_data.get('hosts', []):
                processed_host = self._process_host(host_data, scan_id)
                if processed_host:
                    processed_hosts.append(processed_host)

            # Genera riassunto
            summary = self.parser.get_summary(parsed_data)

            return {
                'scan_id': scan_id,
                'scan_info': scan_info,
                'hosts': processed_hosts,
                'summary': summary,
                'vulnerabilities': self.parser.extract_vulnerabilities(parsed_data)
            }

        except Exception as e:
            logger.error(f"Errore processing scan results: {e}")
            raise

    def _create_scan_record(self, parsed_data: Dict, scan_type: str, xml_content: str) -> Dict[str, Any]:
        """Crea un record della scansione nel database"""
        scan_info = parsed_data.get('scan_info', {})
        stats = parsed_data.get('scan_stats', {})

        scan_data = {
            'scan_type': scan_type,
            'target': self._extract_target_from_args(scan_info.get('args', '')),
            'status': 'completed',
            'nmap_command': scan_info.get('args'),
            'xml_output': xml_content,
            'start_time': self._parse_timestamp(scan_info.get('start')),
            'end_time': self._parse_timestamp(stats.get('finished', {}).get('time')),
            'duration_seconds': self._parse_duration(stats.get('finished', {}).get('elapsed')),
            'hosts_found': len(parsed_data.get('hosts', []))
        }

        scan_id = self.db.insert_scan_record(scan_data)
        scan_data['id'] = scan_id
        return scan_data

    def _extract_target_from_args(self, args: str) -> str:
        """Estrae il target dalla riga di comando di nmap"""
        if not args:
            return "unknown"

        # Cerca pattern IP o range di rete
        import re
        ip_pattern = r'(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?\b)'
        matches = re.findall(ip_pattern, args)

        if matches:
            return matches[-1]  # Ultimo match (probabilmente il target)

        return "unknown"

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Converte un timestamp string in datetime"""
        if not timestamp_str:
            return None

        try:
            return datetime.fromtimestamp(int(timestamp_str))
        except (ValueError, TypeError):
            return None

    def _parse_duration(self, duration_str: str) -> Optional[int]:
        """Converte una stringa di durata in secondi"""
        if not duration_str:
            return None

        try:
            return int(float(duration_str))
        except (ValueError, TypeError):
            return None

    def _process_host(self, host_data: Dict, scan_id: int) -> Optional[Dict[str, Any]]:
        """Processa un singolo host e lo salva nel database"""
        try:
            # Estrai informazioni base dell'host
            host_info = self._extract_host_info(host_data)
            if not host_info:
                return None

            # Arricchisci con informazioni vendor (OUI lookup)
            if host_info.get('mac_address'):
                vendor = self.oui.get_vendor_by_mac(host_info['mac_address'])
                if vendor:
                    host_info['vendor'] = vendor

            # Classifica il tipo di device
            device_type = self.classifier.classify_device(host_info, host_data)
            if device_type:
                host_info['device_type'] = device_type

            # Calcola confidence score
            host_info['confidence_score'] = self._calculate_confidence_score(host_data)

            # Salva nel database
            host_id = self.db.insert_or_update_host(host_info)
            host_info['id'] = host_id

            # Processa le porte
            self._process_host_ports(host_id, host_data, scan_id)

            # Processa le vulnerabilità
            self._process_host_vulnerabilities(host_id, host_data, scan_id)

            # Processa gli script NSE
            self._process_host_scripts(host_id, host_data, scan_id)

            return host_info

        except Exception as e:
            logger.error(f"Errore processing host {host_data}: {e}")
            return None

    def _extract_host_info(self, host_data: Dict) -> Optional[Dict[str, Any]]:
        """Estrae le informazioni base dell'host"""
        host_info = {}

        # Status
        status = host_data.get('status', {})
        if status.get('state') != 'up':
            return None  # Skip host non raggiungibili

        host_info['status'] = status.get('state', 'up')

        # Addresses
        for addr in host_data.get('addresses', []):
            if addr.get('addrtype') == 'ipv4':
                host_info['ip_address'] = addr.get('addr')
            elif addr.get('addrtype') == 'mac':
                host_info['mac_address'] = addr.get('addr')
                if addr.get('vendor'):
                    host_info['vendor'] = addr.get('vendor')

        if not host_info.get('ip_address'):
            return None  # IP obbligatorio

        # Hostnames
        hostnames = host_data.get('hostnames', [])
        if hostnames:
            host_info['hostname'] = hostnames[0].get('name')

        # OS Detection
        os_matches = host_data.get('os', [])
        if os_matches:
            best_os = max(os_matches, key=lambda x: int(x.get('accuracy', 0)))
            host_info['os_name'] = best_os.get('name')
            host_info['os_accuracy'] = int(best_os.get('accuracy', 0))

            # OS Family da osclass
            if best_os.get('osclasses'):
                osclass = best_os['osclasses'][0]
                host_info['os_family'] = osclass.get('osfamily')

        return host_info

    def _calculate_confidence_score(self, host_data: Dict) -> float:
        """Calcola un punteggio di confidenza per la classificazione dell'host"""
        score = 0.0

        # Presenza MAC address (+20%)
        if any(addr.get('addrtype') == 'mac' for addr in host_data.get('addresses', [])):
            score += 0.2

        # Presenza hostname (+15%)
        if host_data.get('hostnames'):
            score += 0.15

        # OS detection con alta accuracy (+25%)
        os_matches = host_data.get('os', [])
        if os_matches:
            best_accuracy = max(int(match.get('accuracy', 0)) for match in os_matches)
            score += (best_accuracy / 100) * 0.25

        # Numero di porte aperte (+30% max)
        open_ports = sum(1 for port in host_data.get('ports', [])
                         if port.get('state', {}).get('state') == 'open')
        score += min(open_ports * 0.05, 0.3)

        # Servizi identificati (+10%)
        services_identified = sum(1 for port in host_data.get('ports', [])
                                  if port.get('service', {}).get('name'))
        if services_identified > 0:
            score += 0.1

        return min(score, 1.0)  # Cap a 1.0

    def _process_host_ports(self, host_id: int, host_data: Dict, scan_id: int):
        """Processa le porte dell'host"""
        from .database_models import PortManager
        port_manager = PortManager(self.db)

        for port_data in host_data.get('ports', []):
            port_info = {
                'protocol': port_data.get('protocol'),
                'port': port_data.get('portid'),
                'state': port_data.get('state', {}).get('state', 'unknown')
            }

            # Service information
            service = port_data.get('service', {})
            port_info.update({
                'service_name': service.get('name'),
                'service_product': service.get('product'),
                'service_version': service.get('version'),
                'service_extrainfo': service.get('extrainfo'),
                'service_ostype': service.get('ostype'),
                'service_method': service.get('method'),
                'service_conf': int(service.get('conf', 0)) if service.get('conf') else None,
                'service_fingerprint': service.get('servicefp'),
                'cpe_list': service.get('cpes', []),
                'banner': service.get('servicefp')
            })

            port_manager.insert_or_update_port(host_id, port_info, scan_id)

    def _process_host_vulnerabilities(self, host_id: int, host_data: Dict, scan_id: int):
        """Processa le vulnerabilità dell'host"""
        from .database_models import VulnerabilityManager
        vuln_manager = VulnerabilityManager(self.db)

        # Estrai vulnerabilità
        vulns = self.parser._extract_host_vulnerabilities(host_data)

        for vuln_data in vulns:
            vuln_info = {
                'host_id': host_id,
                'cve_id': vuln_data.get('cve_id'),
                'vuln_type': vuln_data.get('vuln_type', 'vulnerability'),
                'severity': vuln_data.get('severity') or self.parser._calculate_severity(
                    vuln_data.get('cvss_score', 0)),
                'cvss_score': vuln_data.get('cvss_score'),
                'description': vuln_data.get('description'),
                'exploit_available': vuln_data.get('exploit_available', False),
                'detection_method': vuln_data.get('detection_method')
            }

            vuln_manager.insert_vulnerability(vuln_info)

    def _process_host_scripts(self, host_id: int, host_data: Dict, scan_id: int):
        """Processa i risultati degli script NSE"""
        with self.db.get_connection() as conn:
            # Host scripts
            for script in host_data.get('hostscripts', []):
                self._save_script_result(conn, host_id, None, scan_id, script)

            # Port scripts
            for port_data in host_data.get('ports', []):
                # Trova port_id nel database
                cursor = conn.execute("""
                    SELECT id FROM host_ports 
                    WHERE host_id = ? AND protocol = ? AND port = ?
                """, (host_id, port_data.get('protocol'), port_data.get('portid')))

                port_row = cursor.fetchone()
                if port_row:
                    port_id = port_row['id']

                    for script in port_data.get('scripts', []):
                        self._save_script_result(conn, host_id, port_id, scan_id, script)

            conn.commit()

    def _save_script_result(self, conn, host_id: int, port_id: Optional[int], scan_id: int, script_data: Dict):
        """Salva il risultato di uno script NSE"""
        conn.execute("""
            INSERT INTO nse_scripts (host_id, port_id, scan_id, script_id, script_output, script_data)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            host_id,
            port_id,
            scan_id,
            script_data.get('id'),
            script_data.get('output'),
            json.dumps(script_data.get('data', []))
        ))


# Utility functions
def validate_nmap_xml(xml_content: str) -> bool:
    """Valida se il contenuto XML è un output valido di NMAP"""
    try:
        root = ET.fromstring(xml_content)
        return root.tag == 'nmaprun'
    except ET.ParseError:
        return False


def extract_target_ips(xml_content: str) -> List[str]:
    """Estrae tutti gli IP target dal XML"""
    try:
        parser = NmapXMLParser()
        parsed_data = parser.parse_xml_string(xml_content)

        ips = []
        for host in parsed_data.get('hosts', []):
            for addr in host.get('addresses', []):
                if addr.get('addrtype') == 'ipv4':
                    ips.append(addr.get('addr'))

        return ips
    except Exception:
        return []


def get_scan_statistics(xml_content: str) -> Dict[str, Any]:
    """Estrae statistiche veloci da un XML scan"""
    try:
        parser = NmapXMLParser()
        parsed_data = parser.parse_xml_string(xml_content)
        return parser.get_summary(parsed_data)
    except Exception as e:
        logger.error(f"Errore extracting scan statistics: {e}")
        return {}