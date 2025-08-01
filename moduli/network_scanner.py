"""
Modulo principale per le scansioni di rete
Gestisce l'esecuzione di scansioni NMAP, scheduling e coordinamento
"""
import subprocess
import threading
import time
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import signal
import psutil

from .database_models import DatabaseManager
from .nmap_parser import NmapXMLParser, NmapResultProcessor
from .oui_manager import EnhancedOUIManager
from .device_classifier import DeviceClassifier
from .nvd_manager import NVDManager

logger = logging.getLogger(__name__)


class NmapScanner:
    """Classe per eseguire scansioni NMAP"""

    def __init__(self, config: Dict):
        self.config = config
        self.max_concurrent = config.get('scanning', {}).get('max_concurrent_scans', 3)
        self.timing = config.get('scanning', {}).get('nmap_timing', 'T4')
        self.active_scans = {}
        self.scan_lock = threading.Lock()

    def execute_scan(self, scan_type: str, target: str, options: str = "",
                     callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Esegue una scansione NMAP"""
        scan_id = f"{scan_type}_{target}_{int(time.time())}"

        try:
            # Crea comando nmap
            nmap_cmd = self._build_nmap_command(scan_type, target, options)

            # File temporaneo per output XML
            xml_file = tempfile.mktemp(suffix='.xml', prefix='nmap_')
            nmap_cmd.extend(['-oX', xml_file])

            logger.info(f"Avvio scansione {scan_type}: {' '.join(nmap_cmd)}")

            start_time = datetime.now()

            # Registra scansione attiva
            with self.scan_lock:
                self.active_scans[scan_id] = {
                    'process': None,
                    'start_time': start_time,
                    'target': target,
                    'type': scan_type,
                    'status': 'starting'
                }

            # Esegui comando
            process = subprocess.Popen(
                nmap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Aggiorna processo nella registrazione
            with self.scan_lock:
                self.active_scans[scan_id]['process'] = process
                self.active_scans[scan_id]['status'] = 'running'

            # Attendi completamento
            stdout, stderr = process.communicate()
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # Leggi risultati XML
            xml_content = ""
            if os.path.exists(xml_file):
                with open(xml_file, 'r', encoding='utf-8') as f:
                    xml_content = f.read()
                os.unlink(xml_file)  # Rimuovi file temporaneo

            result = {
                'scan_id': scan_id,
                'success': process.returncode == 0,
                'return_code': process.returncode,
                'start_time': start_time,
                'end_time': end_time,
                'duration_seconds': duration,
                'target': target,
                'scan_type': scan_type,
                'nmap_command': ' '.join(nmap_cmd),
                'xml_output': xml_content,
                'stdout': stdout,
                'stderr': stderr
            }

            # Callback se fornito
            if callback:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Errore callback scansione {scan_id}: {e}")

            logger.info(f"Scansione {scan_id} completata in {duration:.2f}s")

        except Exception as e:
            logger.error(f"Errore esecuzione scansione {scan_id}: {e}")
            result = {
                'scan_id': scan_id,
                'success': False,
                'error': str(e),
                'start_time': start_time,
                'end_time': datetime.now(),
                'target': target,
                'scan_type': scan_type
            }

        finally:
            # Rimuovi dalla lista attive
            with self.scan_lock:
                self.active_scans.pop(scan_id, None)

        return result

    def _build_nmap_command(self, scan_type: str, target: str, options: str = "") -> List[str]:
        """Costruisce il comando nmap basato sul tipo di scansione"""
        cmd = ['nmap']

        # Aggiungi timing
        cmd.append(f'-{self.timing}')

        # Opzioni base per sicurezza
        cmd.extend(['--host-timeout', '300s'])
        cmd.extend(['--max-retries', '2'])

        # Opzioni specifiche per tipo di scansione
        if scan_type == 'discovery':
            cmd.extend(['-sn', '-PE', '-PP', '-PS21,22,23,25,80,113,31339',
                        '-PA80,113,443,10042', '--source-port', '53'])

        elif scan_type == 'quick_scan':
            cmd.extend(['-sS', '--top-ports', '1000'])

        elif scan_type == 'full_scan':
            cmd.extend(['-sS', '-sU', '-O', '-sV', '-sC', '--top-ports', '1000'])

        elif scan_type == 'comprehensive':
            cmd.extend(['-sS', '-sU', '-O', '-sV', '-sC', '--top-ports', '1000',
                        '--script', 'default,safe'])

        elif scan_type == 'vulnerability':
            cmd.extend(['-sV', '--script', 'vuln,exploit'])

        elif scan_type == 'snmp':
            cmd.extend(['-sU', '-p', '161', '--script', 'snmp-*'])

        elif scan_type == 'tcp_connect':
            cmd.extend(['-sT', '--top-ports', '1000'])

        elif scan_type == 'syn_scan':
            cmd.extend(['-sS', '--top-ports', '1000'])

        elif scan_type == 'udp_scan':
            cmd.extend(['-sU', '--top-ports', '100'])

        elif scan_type == 'os_detection':
            cmd.extend(['-O', '-sV'])

        elif scan_type == 'service_scan':
            cmd.extend(['-sV', '-sC'])

        elif scan_type == 'aggressive':
            cmd.extend(['-A'])

        # Aggiungi opzioni personalizzate
        if options:
            cmd.extend(options.split())

        # Aggiungi target
        cmd.append(target)

        return cmd

    def get_active_scans(self) -> Dict[str, Dict]:
        """Restituisce le scansioni attualmente in corso"""
        with self.scan_lock:
            return self.active_scans.copy()

    def kill_scan(self, scan_id: str) -> bool:
        """Termina una scansione in corso"""
        with self.scan_lock:
            if scan_id in self.active_scans:
                process = self.active_scans[scan_id].get('process')
                if process:
                    try:
                        # Termina processo e figli
                        parent = psutil.Process(process.pid)
                        children = parent.children(recursive=True)

                        for child in children:
                            child.terminate()
                        parent.terminate()

                        # Attendi terminazione
                        gone, alive = psutil.wait_procs(children + [parent], timeout=10)

                        # Force kill se necessario
                        for p in alive:
                            p.kill()

                        self.active_scans[scan_id]['status'] = 'killed'
                        logger.info(f"Scansione {scan_id} terminata")
                        return True

                    except Exception as e:
                        logger.error(f"Errore terminazione scansione {scan_id}: {e}")
                        return False

        return False

    def kill_all_scans(self):
        """Termina tutte le scansioni in corso"""
        with self.scan_lock:
            scan_ids = list(self.active_scans.keys())

        for scan_id in scan_ids:
            self.kill_scan(scan_id)


class ScanScheduler:
    """Scheduler nativo Python per scansioni automatiche"""

    def __init__(self, scanner: NmapScanner, db_manager: DatabaseManager):
        self.scanner = scanner
        self.db = db_manager
        self.scheduled_jobs = {}
        self.scheduler_thread = None
        self.running = False
        self.job_lock = threading.Lock()

    def start(self):
        """Avvia lo scheduler"""
        if self.running:
            return

        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        logger.info("Scheduler avviato")

    def stop(self):
        """Ferma lo scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("Scheduler fermato")

    def _scheduler_loop(self):
        """Loop principale dello scheduler"""
        while self.running:
            try:
                current_time = datetime.now()

                # Controlla job schedulati
                with self.job_lock:
                    jobs_to_run = []
                    for job_id, job_info in self.scheduled_jobs.items():
                        if current_time >= job_info['next_run'] and job_info['enabled']:
                            jobs_to_run.append((job_id, job_info))

                # Esegui job
                for job_id, job_info in jobs_to_run:
                    try:
                        self._execute_scheduled_job(job_id, job_info)
                    except Exception as e:
                        logger.error(f"Errore esecuzione job {job_id}: {e}")

                # Attendi prima del prossimo controllo
                time.sleep(60)  # Controlla ogni minuto

            except Exception as e:
                logger.error(f"Errore nel scheduler loop: {e}")
                time.sleep(60)

    def add_job(self, job_id: str, scan_type: str, target: str,
                interval_minutes: int, options: str = "", enabled: bool = True):
        """Aggiunge un job allo scheduler"""
        next_run = datetime.now() + timedelta(minutes=1)  # Primo run tra 1 minuto

        job_info = {
            'scan_type': scan_type,
            'target': target,
            'interval_minutes': interval_minutes,
            'options': options,
            'enabled': enabled,
            'next_run': next_run,
            'last_run': None,
            'run_count': 0
        }

        with self.job_lock:
            self.scheduled_jobs[job_id] = job_info

        logger.info(f"Job {job_id} aggiunto: {scan_type} su {target} ogni {interval_minutes} minuti")

    def remove_job(self, job_id: str):
        """Rimuove un job dallo scheduler"""
        with self.job_lock:
            self.scheduled_jobs.pop(job_id, None)
        logger.info(f"Job {job_id} rimosso")

    def enable_job(self, job_id: str, enabled: bool = True):
        """Abilita/disabilita un job"""
        with self.job_lock:
            if job_id in self.scheduled_jobs:
                self.scheduled_jobs[job_id]['enabled'] = enabled
                status = "abilitato" if enabled else "disabilitato"
                logger.info(f"Job {job_id} {status}")

    def get_jobs(self) -> Dict[str, Dict]:
        """Restituisce tutti i job schedulati"""
        with self.job_lock:
            return {k: v.copy() for k, v in self.scheduled_jobs.items()}

    def _execute_scheduled_job(self, job_id: str, job_info: Dict):
        """Esegue un job schedulato"""
        logger.info(f"Esecuzione job schedulato: {job_id}")

        # Esegui scansione in background
        def job_callback(result):
            logger.info(f"Job {job_id} completato: {result.get('success', False)}")

        # Avvia scansione
        threading.Thread(
            target=self.scanner.execute_scan,
            args=(job_info['scan_type'], job_info['target'], job_info['options'], job_callback),
            daemon=True
        ).start()

        # Aggiorna job info
        with self.job_lock:
            job_info['last_run'] = datetime.now()
            job_info['run_count'] += 1
            job_info['next_run'] = datetime.now() + timedelta(minutes=job_info['interval_minutes'])

    def load_jobs_from_config(self, config: Dict):
        """Carica job dalla configurazione"""
        scan_configs = [
            ('discovery', 'discovery', config.get('scanning', {}).get('network_range', '192.168.1.0/24'),
             config.get('scanning', {}).get('discovery_interval_minutes', 60), '-sn'),

            ('full_scan', 'comprehensive', config.get('scanning', {}).get('network_range', '192.168.1.0/24'),
             config.get('scanning', {}).get('full_scan_interval_minutes', 1440), ''),

            ('vuln_scan', 'vulnerability', config.get('scanning', {}).get('network_range', '192.168.1.0/24'),
             config.get('scanning', {}).get('vulnerability_scan_interval_minutes', 4320), ''),

            ('snmp_scan', 'snmp', config.get('scanning', {}).get('network_range', '192.168.1.0/24'),
             config.get('scanning', {}).get('snmp_scan_interval_minutes', 720), '')
        ]

        for job_id, scan_type, target, interval, options in scan_configs:
            self.add_job(job_id, scan_type, target, interval, options)


class NetworkScanManager:
    """Manager principale per tutte le operazioni di scanning"""

    def __init__(self, config_file: str = 'scan_config.json'):
        self.config = self._load_config(config_file)

        # Inizializza componenti
        self.db = DatabaseManager(self.config.get('database', {}).get('path', 'instance/network_inventory.db'))
        self.oui_manager = EnhancedOUIManager(self.db, self.config)
        self.device_classifier = DeviceClassifier(self.config)
        self.nvd_manager = NVDManager(self.db, self.config)

        # Parser e processor
        self.parser = NmapXMLParser()
        self.processor = NmapResultProcessor(self.db, self.oui_manager, self.device_classifier)

        # Scanner e scheduler
        self.scanner = NmapScanner(self.config)
        self.scheduler = ScanScheduler(self.scanner, self.db)

        # Executor per scansioni parallele
        self.executor = ThreadPoolExecutor(max_workers=self.config.get('scanning', {}).get('max_concurrent_scans', 3))

        # Setup logging
        self._setup_logging()

        logger.info("NetworkScanManager inizializzato")

    def _load_config(self, config_file: str) -> Dict:
        """Carica configurazione da file JSON"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"File configurazione {config_file} non trovato, uso defaults")
            return self._get_default_config()
        except json.JSONDecodeError as e:
            logger.error(f"Errore parsing configurazione: {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict:
        """Configurazione di default"""
        return {
            'scanning': {
                'network_range': '192.168.1.0/24',
                'discovery_interval_minutes': 60,
                'full_scan_interval_minutes': 1440,
                'max_concurrent_scans': 3,
                'nmap_timing': 'T4'
            },
            'database': {
                'path': 'instance/network_inventory.db'
            }
        }

    def _setup_logging(self):
        """Configura logging"""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO'))

        # Crea directory log se non esiste
        log_file = log_config.get('file', 'instance/logs/scanner.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        # Configura logger
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def start(self):
        """Avvia il sistema di scanning"""
        logger.info("Avvio NetworkScanManager")

        # Aggiorna database OUI se necessario
        if self.oui_manager.needs_update():
            logger.info("Aggiornamento database OUI")
            self.oui_manager.update_database()

        # Aggiorna database NVD se necessario
        if self.nvd_manager.needs_update():
            logger.info("Aggiornamento database NVD")
            self.nvd_manager.update_nvd_database()

        # Avvia scheduler
        self.scheduler.load_jobs_from_config(self.config)
        self.scheduler.start()

        logger.info("NetworkScanManager avviato con successo")

    def stop(self):
        """Ferma il sistema di scanning"""
        logger.info("Arresto NetworkScanManager")

        # Ferma scheduler
        self.scheduler.stop()

        # Termina scansioni attive
        self.scanner.kill_all_scans()

        # Shutdown executor
        self.executor.shutdown(wait=True, timeout=30)

        logger.info("NetworkScanManager arrestato")

    def execute_manual_scan(self, scan_type: str, target: str, options: str = "") -> Dict[str, Any]:
        """Esegue una scansione manuale"""
        logger.info(f"Avvio scansione manuale: {scan_type} su {target}")

        def process_callback(result):
            if result.get('success') and result.get('xml_output'):
                try:
                    processed = self.processor.process_scan_results(
                        result['xml_output'], scan_type
                    )
                    logger.info(f"Processati {len(processed.get('hosts', []))} host dalla scansione")
                except Exception as e:
                    logger.error(f"Errore processing risultati scansione: {e}")

        return self.scanner.execute_scan(scan_type, target, options, process_callback)

    def execute_async_scan(self, scan_type: str, target: str, options: str = ""):
        """Esegue una scansione asincrona"""
        future = self.executor.submit(self.execute_manual_scan, scan_type, target, options)
        return future

    def get_network_inventory(self) -> Dict[str, Any]:
        """Recupera l'inventario completo della rete"""
        hosts = self.db.get_all_hosts()

        inventory = {
            'total_hosts': len(hosts),
            'hosts_by_type': {},
            'hosts_by_status': {},
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'hosts': []
        }

        for host in hosts:
            # Statistiche per tipo
            device_type = host.get('device_type', 'unknown')
            inventory['hosts_by_type'][device_type] = inventory['hosts_by_type'].get(device_type, 0) + 1

            # Statistiche per status
            status = host.get('status', 'unknown')
            inventory['hosts_by_status'][status] = inventory['hosts_by_status'].get(status, 0) + 1

            # Arricchisci dati host
            host_data = dict(host)
            host_data['ports'] = self.db.get_host_ports(host['id'])
            host_data['vulnerabilities'] = self.db.get_host_vulnerabilities(host['id'])

            # Conta vulnerabilità
            inventory['total_vulnerabilities'] += len(host_data['vulnerabilities'])
            inventory['critical_vulnerabilities'] += len([
                v for v in host_data['vulnerabilities']
                if v.get('cvss_score', 0) >= 9.0
            ])

            inventory['hosts'].append(host_data)

        return inventory

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Recupera la cronologia delle scansioni"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM scans 
                ORDER BY start_time DESC 
                LIMIT ?
            """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def get_system_status(self) -> Dict[str, Any]:
        """Restituisce lo stato del sistema"""
        return {
            'active_scans': len(self.scanner.get_active_scans()),
            'scheduled_jobs': len(self.scheduler.get_jobs()),
            'database_stats': {
                'total_hosts': len(self.db.get_all_hosts()),
                'active_hosts': len(self.db.get_all_hosts(active_only=True))
            },
            'oui_stats': self.oui_manager.standard_oui.get_stats(),
            'nvd_stats': self.nvd_manager.get_nvd_stats(),
            'last_discovery': self._get_last_scan_time('discovery'),
            'last_full_scan': self._get_last_scan_time('comprehensive'),
            'last_vuln_scan': self._get_last_scan_time('vulnerability')
        }

    def _get_last_scan_time(self, scan_type: str) -> Optional[str]:
        """Recupera timestamp dell'ultima scansione di un tipo"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT MAX(start_time) as last_scan
                FROM scans
                WHERE scan_type = ? AND status = 'completed'
            """, (scan_type,))

            row = cursor.fetchone()
            return row['last_scan'] if row and row['last_scan'] else None

    def import_nmap_xml(self, xml_file_path: str, scan_type: str = "imported") -> Dict[str, Any]:
        """Importa risultati da file XML di NMAP esistente"""
        try:
            with open(xml_file_path, 'r', encoding='utf-8') as f:
                xml_content = f.read()

            # Processa risultati
            processed = self.processor.process_scan_results(xml_content, scan_type)

            logger.info(f"Importati {len(processed.get('hosts', []))} host da {xml_file_path}")
            return processed

        except Exception as e:
            logger.error(f"Errore importazione XML {xml_file_path}: {e}")
            raise

    def export_inventory(self, output_file: str, format: str = "json"):
        """Esporta l'inventario di rete"""
        inventory = self.get_network_inventory()

        if format.lower() == "json":
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(inventory, f, indent=2, default=str)

        elif format.lower() == "csv":
            import csv

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)

                # Header
                writer.writerow([
                    'IP Address', 'MAC Address', 'Hostname', 'Vendor',
                    'Device Type', 'OS Name', 'Status', 'Open Ports',
                    'Vulnerabilities', 'Last Seen'
                ])

                # Data
                for host in inventory['hosts']:
                    open_ports = len([p for p in host.get('ports', []) if p.get('state') == 'open'])
                    vuln_count = len(host.get('vulnerabilities', []))

                    writer.writerow([
                        host.get('ip_address', ''),
                        host.get('mac_address', ''),
                        host.get('hostname', ''),
                        host.get('vendor', ''),
                        host.get('device_type', ''),
                        host.get('os_name', ''),
                        host.get('status', ''),
                        open_ports,
                        vuln_count,
                        host.get('last_seen', '')
                    ])

        logger.info(f"Inventario esportato in {output_file} (formato: {format})")

    def generate_report(self, report_type: str = "summary") -> Dict[str, Any]:
        """Genera report di sicurezza"""
        inventory = self.get_network_inventory()

        if report_type == "summary":
            return self._generate_summary_report(inventory)
        elif report_type == "vulnerabilities":
            return self._generate_vulnerability_report(inventory)
        elif report_type == "topology":
            from .device_classifier import NetworkTopologyAnalyzer
            analyzer = NetworkTopologyAnalyzer(self.db)
            return analyzer.analyze_network_topology()
        else:
            raise ValueError(f"Report type non supportato: {report_type}")

    def _generate_summary_report(self, inventory: Dict[str, Any]) -> Dict[str, Any]:
        """Genera report riassuntivo"""
        return {
            'report_type': 'summary',
            'generated_at': datetime.now().isoformat(),
            'network_overview': {
                'total_devices': inventory['total_hosts'],
                'active_devices': inventory['hosts_by_status'].get('up', 0),
                'device_types': inventory['hosts_by_type'],
                'total_vulnerabilities': inventory['total_vulnerabilities'],
                'critical_vulnerabilities': inventory['critical_vulnerabilities']
            },
            'top_vulnerabilities': self._get_top_vulnerabilities(),
            'device_distribution': inventory['hosts_by_type'],
            'security_score': self._calculate_network_security_score(inventory),
            'recommendations': self._generate_security_recommendations(inventory)
        }

    def _generate_vulnerability_report(self, inventory: Dict[str, Any]) -> Dict[str, Any]:
        """Genera report focalizzato sulle vulnerabilità"""
        all_vulns = []
        for host in inventory['hosts']:
            for vuln in host.get('vulnerabilities', []):
                vuln['host_ip'] = host.get('ip_address')
                vuln['hostname'] = host.get('hostname')
                all_vulns.append(vuln)

        # Raggruppa per severità
        vulns_by_severity = {}
        for vuln in all_vulns:
            severity = vuln.get('severity', 'unknown')
            if severity not in vulns_by_severity:
                vulns_by_severity[severity] = []
            vulns_by_severity[severity].append(vuln)

        return {
            'report_type': 'vulnerabilities',
            'generated_at': datetime.now().isoformat(),
            'total_vulnerabilities': len(all_vulns),
            'vulnerabilities_by_severity': {
                k: len(v) for k, v in vulns_by_severity.items()
            },
            'critical_vulnerabilities': vulns_by_severity.get('critical', []),
            'high_vulnerabilities': vulns_by_severity.get('high', []),
            'top_cves': self._get_most_common_cves(all_vulns),
            'affected_hosts': len(set(v.get('host_ip') for v in all_vulns if v.get('host_ip')))
        }

    def _get_top_vulnerabilities(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Recupera le vulnerabilità più critiche"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT h.ip_address, h.hostname, v.cve_id, v.cvss_score, 
                       v.severity, v.description
                FROM vulnerabilities v
                JOIN hosts h ON v.host_id = h.id
                WHERE v.status = 'open'
                ORDER BY v.cvss_score DESC
                LIMIT ?
            """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def _get_most_common_cves(self, vulnerabilities: List[Dict]) -> List[Dict[str, Any]]:
        """Trova i CVE più comuni"""
        cve_counts = {}
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id')
            if cve_id:
                if cve_id not in cve_counts:
                    cve_counts[cve_id] = {
                        'cve_id': cve_id,
                        'count': 0,
                        'max_score': 0,
                        'severity': vuln.get('severity', 'unknown')
                    }
                cve_counts[cve_id]['count'] += 1
                cve_counts[cve_id]['max_score'] = max(
                    cve_counts[cve_id]['max_score'],
                    vuln.get('cvss_score', 0)
                )

        return sorted(cve_counts.values(), key=lambda x: x['count'], reverse=True)[:10]

    def _calculate_network_security_score(self, inventory: Dict[str, Any]) -> float:
        """Calcola score di sicurezza della rete"""
        if inventory['total_hosts'] == 0:
            return 100.0

        score = 100.0

        # Penalità per vulnerabilità
        vuln_ratio = inventory['total_vulnerabilities'] / inventory['total_hosts']
        score -= min(vuln_ratio * 10, 40)

        # Penalità extra per vulnerabilità critiche
        if inventory['critical_vulnerabilities'] > 0:
            critical_ratio = inventory['critical_vulnerabilities'] / inventory['total_hosts']
            score -= min(critical_ratio * 30, 30)

        # Penalità per dispositivi non classificati
        unknown_devices = inventory['hosts_by_type'].get('unknown', 0)
        unknown_ratio = unknown_devices / inventory['total_hosts']
        score -= unknown_ratio * 20

        return max(0.0, score)

    def _generate_security_recommendations(self, inventory: Dict[str, Any]) -> List[str]:
        """Genera raccomandazioni di sicurezza"""
        recommendations = []

        if inventory['critical_vulnerabilities'] > 0:
            recommendations.append(
                f"URGENTE: Risolvere {inventory['critical_vulnerabilities']} vulnerabilità critiche"
            )

        if inventory['total_vulnerabilities'] > inventory['total_hosts']:
            recommendations.append(
                "Alto numero di vulnerabilità per dispositivo - implementare patch management"
            )

        unknown_count = inventory['hosts_by_type'].get('unknown', 0)
        if unknown_count > 0:
            recommendations.append(
                f"Classificare {unknown_count} dispositivi non identificati"
            )

        iot_count = inventory['hosts_by_type'].get('iot', 0)
        if iot_count > 0:
            recommendations.append(
                f"Considerare isolamento VLAN per {iot_count} dispositivi IoT"
            )

        if inventory['hosts_by_status'].get('up', 0) > 50:
            recommendations.append(
                "Rete di grandi dimensioni - considerare segmentazione"
            )

        return recommendations

    def perform_maintenance(self):
        """Esegue operazioni di manutenzione"""
        logger.info("Avvio manutenzione database")

        # Pulisci dati vecchi
        cleanup_days = self.config.get('database', {}).get('cleanup_old_scans_days', 90)
        self.db.cleanup_old_data(cleanup_days)

        # Aggiorna database OUI se necessario
        if self.oui_manager.needs_update():
            self.oui_manager.update_database()

        # Aggiorna database NVD se necessario
        if self.nvd_manager.needs_update():
            self.nvd_manager.update_nvd_database()

        logger.info("Manutenzione completata")


class ScanTemplateManager:
    """Gestore per template di scansione predefiniti"""

    def __init__(self, config: Dict):
        self.config = config
        self.templates = self._load_default_templates()

    def _load_default_templates(self) -> Dict[str, Dict]:
        """Carica template di scansione predefiniti"""
        return {
            'network_discovery': {
                'name': 'Network Discovery',
                'description': 'Scoperta rapida di host attivi',
                'scan_type': 'discovery',
                'options': '-sn -PE -PP -PS21,22,23,25,80,113,31339',
                'estimated_time': '2-5 minuti',
                'suitable_for': ['Scoperta iniziale', 'Monitoraggio hosts']
            },
            'port_scan_top1000': {
                'name': 'Port Scan Top 1000',
                'description': 'Scansione delle 1000 porte più comuni',
                'scan_type': 'quick_scan',
                'options': '-sS --top-ports 1000',
                'estimated_time': '5-15 minuti',
                'suitable_for': ['Analisi servizi', 'Identificazione servizi']
            },
            'comprehensive_scan': {
                'name': 'Scansione Completa',
                'description': 'Scansione completa con OS e service detection',
                'scan_type': 'comprehensive',
                'options': '-sS -sU -O -sV -sC --top-ports 1000',
                'estimated_time': '30-60 minuti',
                'suitable_for': ['Audit completo', 'Inventario dettagliato']
            },
            'vulnerability_assessment': {
                'name': 'Vulnerability Assessment',
                'description': 'Scansione focalizzata su vulnerabilità',
                'scan_type': 'vulnerability',
                'options': '-sV --script vuln,exploit',
                'estimated_time': '20-45 minuti',
                'suitable_for': ['Security audit', 'Penetration testing']
            },
            'stealth_scan': {
                'name': 'Stealth Scan',
                'description': 'Scansione discreta per evitare detection',
                'scan_type': 'syn_scan',
                'options': '-sS -T2 --randomize-hosts',
                'estimated_time': '45-90 minuti',
                'suitable_for': ['Red team', 'Analisi stealth']
            },
            'snmp_enumeration': {
                'name': 'SNMP Enumeration',
                'description': 'Enumerazione servizi SNMP',
                'scan_type': 'snmp',
                'options': '-sU -p 161 --script snmp-*',
                'estimated_time': '10-20 minuti',
                'suitable_for': ['Network devices', 'Monitoring systems']
            },
            'web_services_scan': {
                'name': 'Web Services Scan',
                'description': 'Scansione focalizzata su servizi web',
                'scan_type': 'service_scan',
                'options': '-sS -p 80,443,8080,8443 --script http-*',
                'estimated_time': '15-30 minuti',
                'suitable_for': ['Web applications', 'HTTP services']
            },
            'database_scan': {
                'name': 'Database Services Scan',
                'description': 'Identificazione servizi database',
                'scan_type': 'service_scan',
                'options': '-sS -p 1433,3306,5432,1521,27017 --script database',
                'estimated_time': '10-15 minuti',
                'suitable_for': ['Database servers', 'SQL services']
            }
        }

    def get_template(self, template_name: str) -> Optional[Dict[str, Any]]:
        """Recupera un template per nome"""
        return self.templates.get(template_name)

    def get_all_templates(self) -> Dict[str, Dict]:
        """Recupera tutti i template disponibili"""
        return self.templates.copy()

    def add_custom_template(self, name: str, template_data: Dict[str, Any]):
        """Aggiunge un template personalizzato"""
        self.templates[name] = template_data
        logger.info(f"Template personalizzato '{name}' aggiunto")

    def get_recommended_template(self, network_size: str, security_level: str) -> str:
        """Raccomanda un template basato su dimensioni di rete e livello di sicurezza"""
        if network_size == 'small' and security_level == 'basic':
            return 'network_discovery'
        elif network_size == 'small' and security_level == 'high':
            return 'comprehensive_scan'
        elif network_size == 'large' and security_level == 'basic':
            return 'port_scan_top1000'
        elif network_size == 'large' and security_level == 'high':
            return 'vulnerability_assessment'
        else:
            return 'port_scan_top1000'


def normalize_network_range(network_range):
    """
    Normalizza il parametro network_range in modo che sia sempre una lista di stringhe.

    Args:
        network_range: Può essere una stringa singola o una lista di stringhe

    Returns:
        list: Lista di subnet come stringhe
    """
    if isinstance(network_range, str):
        return [network_range]
    elif isinstance(network_range, list):
        return [str(subnet) for subnet in network_range]  # Assicura che siano stringhe
    else:
        raise ValueError(f"network_range deve essere str o list, ricevuto: {type(network_range)}")

# Funzioni di utility per l'integrazione
def validate_target(target: str) -> bool:
    """Valida un target di scansione"""
    import re

    # IP singolo
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}'
    if re.match(ip_pattern, target):
        return True

    # Range CIDR
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}'
    if re.match(cidr_pattern, target):
        return True

    # Range IP
    range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}'
    if re.match(range_pattern, target):
        return True

    # Hostname
    hostname_pattern = r'^[a-zA-Z0-9.-]+'
    if re.match(hostname_pattern, target):
        return True

    return False


def estimate_scan_time(scan_type: str, target: str) -> str:
    """Stima il tempo di scansione"""
    # Calcola numero approssimativo di host
    if '/' in target:  # CIDR
        cidr_suffix = int(target.split('/')[-1])
        host_count = 2 ** (32 - cidr_suffix) - 2
    elif '-' in target:  # Range
        start_ip = int(target.split('-')[0].split('.')[-1])
        end_ip = int(target.split('-')[1])
        host_count = end_ip - start_ip + 1
    else:  # Singolo host
        host_count = 1

    # Tempo base per tipo di scansione (secondi per host)
    time_per_host = {
        'discovery': 0.5,
        'quick_scan': 5,
        'comprehensive': 30,
        'vulnerability': 20,
        'snmp': 2
    }

    base_time = time_per_host.get(scan_type, 10)
    total_seconds = host_count * base_time

    if total_seconds < 60:
        return f"{int(total_seconds)} secondi"
    elif total_seconds < 3600:
        return f"{int(total_seconds / 60)} minuti"
    else:
        return f"{int(total_seconds / 3600)} ore"


def get_nmap_version() -> Optional[str]:
    """Recupera la versione di NMAP installata"""
    try:
        result = subprocess.run(['nmap', '--version'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            return version_line.split()[-1] if version_line else None
    except Exception:
        pass

    return None


def check_nmap_availability() -> Dict[str, Any]:
    """Controlla disponibilità e capacità di NMAP"""
    status = {
        'available': False,
        'version': None,
        'can_run_as_root': False,
        'scripts_available': False,
        'error': None
    }

    try:
        # Controlla versione
        version = get_nmap_version()
        if version:
            status['available'] = True
            status['version'] = version
        else:
            status['error'] = "NMAP non trovato nel PATH"
            return status

        # Controlla privilegi root
        try:
            result = subprocess.run(['nmap', '-sS', '--privileged', '127.0.0.1'],
                                    capture_output=True, timeout=10)
            status['can_run_as_root'] = result.returncode == 0
        except Exception:
            status['can_run_as_root'] = False

        # Controlla script NSE
        try:
            result = subprocess.run(['nmap', '--script-help', 'vuln'],
                                    capture_output=True, timeout=10)
            status['scripts_available'] = result.returncode == 0
        except Exception:
            status['scripts_available'] = False

    except Exception as e:
        status['error'] = str(e)

    return status

