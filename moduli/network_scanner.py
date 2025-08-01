"""
Modulo principale per le scansioni di rete
Gestisce l'esecuzione di scansioni NMAP, scheduling e coordinamento
Versione corretta con supporto per multiple subnet
"""
import subprocess
import threading
import time
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
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


def normalize_network_range(network_range: Union[str, List[str]]) -> List[str]:
    """
    Normalizza il parametro network_range in modo che sia sempre una lista di stringhe.

    Args:
        network_range: Può essere una stringa singola o una lista di stringhe

    Returns:
        list: Lista di subnet come stringhe
    """
    if isinstance(network_range, str):
        # Se è una stringa, potrebbe essere una singola subnet o multiple separate da spazi
        if ' ' in network_range:
            return [subnet.strip() for subnet in network_range.split() if subnet.strip()]
        else:
            return [network_range]
    elif isinstance(network_range, list):
        # Assicura che tutti gli elementi siano stringhe
        return [str(subnet).strip() for subnet in network_range if str(subnet).strip()]
    else:
        raise ValueError(f"network_range deve essere str o list, ricevuto: {type(network_range)}")


def format_targets_for_nmap(network_ranges: List[str]) -> str:
    """
    Formatta una lista di subnet per l'uso con nmap.

    Args:
        network_ranges: Lista di subnet

    Returns:
        Stringa con target separati da spazi per nmap
    """
    return ' '.join(network_ranges)


class NmapScanner:
    """Classe per eseguire scansioni NMAP con supporto multi-subnet"""

    def __init__(self, config: Dict):
        self.config = config
        self.max_concurrent = config.get('scanning', {}).get('max_concurrent_scans', 3)
        self.timing = config.get('scanning', {}).get('nmap_timing', 'T4')
        self.active_scans = {}
        self.scan_lock = threading.Lock()

        # Normalizza network_range dalla configurazione
        raw_network_range = config.get('scanning', {}).get('network_range', '192.168.1.0/24')
        self.network_ranges = normalize_network_range(raw_network_range)

        logger.info(f"NmapScanner inizializzato con {len(self.network_ranges)} subnet: {self.network_ranges}")

    def execute_scan(self, scan_type: str, target: Union[str, List[str]], options: str = "",
                     callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Esegue una scansione NMAP con supporto per target multipli

        Args:
            scan_type: Tipo di scansione
            target: Target singolo (str) o multipli (List[str])
            options: Opzioni aggiuntive
            callback: Callback da chiamare al completamento
        """
        # Normalizza target
        if isinstance(target, str):
            target_list = [target]
            target_display = target
        else:
            target_list = normalize_network_range(target)
            target_display = f"[{len(target_list)} subnet]"

        scan_id = f"{scan_type}_{target_display}_{int(time.time())}"

        try:
            # Crea comando nmap per target multipli
            nmap_cmd = self._build_nmap_command(scan_type, target_list, options)

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
                    'target': target_display,
                    'target_list': target_list,
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
                'target': target_display,
                'target_list': target_list,
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
                'target': target_display,
                'target_list': target_list if 'target_list' in locals() else [],
                'scan_type': scan_type
            }

        finally:
            # Rimuovi dalla lista attive
            with self.scan_lock:
                self.active_scans.pop(scan_id, None)

        return result

    def _build_nmap_command(self, scan_type: str, target_list: List[str], options: str = "") -> List[str]:
        """
        Costruisce il comando nmap basato sul tipo di scansione e target multipli

        Args:
            scan_type: Tipo di scansione
            target_list: Lista di target
            options: Opzioni aggiuntive

        Returns:
            Lista di stringhe che formano il comando nmap
        """
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

        # FIX IMPORTANTE: Aggiungi target come stringhe separate
        # Nmap può gestire multiple target separandoli con spazi
        cmd.extend(target_list)

        return cmd

    def execute_scan_for_networks(self, scan_type: str, options: str = "",
                                  callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Esegue una scansione su tutte le subnet configurate

        Args:
            scan_type: Tipo di scansione
            options: Opzioni aggiuntive
            callback: Callback da chiamare al completamento

        Returns:
            Risultato della scansione
        """
        logger.info(f"Avvio scansione {scan_type} su {len(self.network_ranges)} subnet")
        return self.execute_scan(scan_type, self.network_ranges, options, callback)

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
    """Scheduler nativo Python per scansioni automatiche con supporto multi-subnet"""

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

    def add_job(self, job_id: str, scan_type: str, target: Union[str, List[str]],
                interval_minutes: int, options: str = "", enabled: bool = True):
        """
        Aggiunge un job allo scheduler con supporto per target multipli

        Args:
            job_id: ID univoco del job
            scan_type: Tipo di scansione
            target: Target singolo o lista di target
            interval_minutes: Intervallo in minuti
            options: Opzioni aggiuntive
            enabled: Se il job è abilitato
        """
        next_run = datetime.now() + timedelta(minutes=1)  # Primo run tra 1 minuto

        # Normalizza target
        if isinstance(target, str):
            target_list = [target]
            target_display = target
        else:
            target_list = normalize_network_range(target)
            target_display = f"[{len(target_list)} subnet]"

        job_info = {
            'scan_type': scan_type,
            'target': target_display,
            'target_list': target_list,
            'interval_minutes': interval_minutes,
            'options': options,
            'enabled': enabled,
            'next_run': next_run,
            'last_run': None,
            'run_count': 0
        }

        with self.job_lock:
            self.scheduled_jobs[job_id] = job_info

        logger.info(f"Job {job_id} aggiunto: {scan_type} su {target_display} ogni {interval_minutes} minuti")

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

        # Avvia scansione con target multipli
        threading.Thread(
            target=self.scanner.execute_scan,
            args=(job_info['scan_type'], job_info['target_list'], job_info['options'], job_callback),
            daemon=True
        ).start()

        # Aggiorna job info
        with self.job_lock:
            job_info['last_run'] = datetime.now()
            job_info['run_count'] += 1
            job_info['next_run'] = datetime.now() + timedelta(minutes=job_info['interval_minutes'])

    def load_jobs_from_config(self, config: Dict):
        """Carica job dalla configurazione con supporto multi-subnet"""

        # Ottieni network_range normalizzato
        raw_network_range = config.get('scanning', {}).get('network_range', '192.168.1.0/24')
        network_ranges = normalize_network_range(raw_network_range)

        scan_configs = [
            ('discovery', 'discovery', network_ranges,
             config.get('scanning', {}).get('discovery_interval_minutes', 60), '-sn'),

            ('full_scan', 'comprehensive', network_ranges,
             config.get('scanning', {}).get('full_scan_interval_minutes', 1440), ''),

            ('vuln_scan', 'vulnerability', network_ranges,
             config.get('scanning', {}).get('vulnerability_scan_interval_minutes', 4320), ''),

            ('snmp_scan', 'snmp', network_ranges,
             config.get('scanning', {}).get('snmp_scan_interval_minutes', 720), '')
        ]

        for job_id, scan_type, target, interval, options in scan_configs:
            self.add_job(job_id, scan_type, target, interval, options)


class NetworkScanManager:
    """Manager principale per tutte le operazioni di scanning con supporto multi-subnet"""

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

        # Scanner e scheduler con supporto multi-subnet
        self.scanner = NmapScanner(self.config)
        self.scheduler = ScanScheduler(self.scanner, self.db)

        # Executor per scansioni parallele
        self.executor = ThreadPoolExecutor(max_workers=self.config.get('scanning', {}).get('max_concurrent_scans', 3))

        # Setup logging
        self._setup_logging()

        # Network ranges normalizzate
        raw_network_range = self.config.get('scanning', {}).get('network_range', '192.168.1.0/24')
        self.network_ranges = normalize_network_range(raw_network_range)

        logger.info(f"NetworkScanManager inizializzato con {len(self.network_ranges)} subnet: {self.network_ranges}")

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
                'vulnerability_scan_interval_minutes': 4320,
                'snmp_scan_interval_minutes': 720,
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
        if hasattr(self.oui_manager, 'needs_update') and self.oui_manager.needs_update():
            logger.info("Aggiornamento database OUI")
            if hasattr(self.oui_manager, 'update_database'):
                self.oui_manager.update_database()

        # Aggiorna database NVD se necessario
        if hasattr(self.nvd_manager, 'needs_update') and self.nvd_manager.needs_update():
            logger.info("Aggiornamento database NVD")
            if hasattr(self.nvd_manager, 'update_nvd_database'):
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

    def execute_manual_scan(self, scan_type: str, target: Union[str, List[str]] = None, options: str = "") -> Dict[str, Any]:
        """
        Esegue una scansione manuale

        Args:
            scan_type: Tipo di scansione
            target: Target specifico o None per usare le subnet configurate
            options: Opzioni aggiuntive

        Returns:
            Risultato della scansione
        """
        # Se non viene specificato un target, usa le subnet configurate
        if target is None:
            target = self.network_ranges
            target_display = f"configurate ({len(self.network_ranges)} subnet)"
        else:
            target_display = str(target)

        logger.info(f"Avvio scansione manuale: {scan_type} su {target_display}")

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

    def execute_async_scan(self, scan_type: str, target: Union[str, List[str]] = None, options: str = ""):
        """Esegue una scansione asincrona"""
        future = self.executor.submit(self.execute_manual_scan, scan_type, target, options)
        return future

    # Metodi di scansione specifici per compatibilità
    def execute_discovery_scan(self) -> Dict[str, Any]:
        """Esegue discovery scan su tutte le subnet configurate"""
        return self.scanner.execute_scan_for_networks('discovery')

    def execute_comprehensive_scan(self) -> Dict[str, Any]:
        """Esegue comprehensive scan su tutte le subnet configurate"""
        return self.scanner.execute_scan_for_networks('comprehensive')

    def execute_vulnerability_scan(self) -> Dict[str, Any]:
        """Esegue vulnerability scan su tutte le subnet configurate"""
        return self.scanner.execute_scan_for_networks('vulnerability')

    def execute_snmp_scan(self) -> Dict[str, Any]:
        """Esegue SNMP scan su tutte le subnet configurate"""
        return self.scanner.execute_scan_for_networks('snmp')

    def get_network_inventory(self) -> Dict[str, Any]:
        """Recupera l'inventario completo della rete"""
        hosts = self.db.get_all_hosts()

        inventory = {
            'total_hosts': len(hosts),
            'hosts_by_type': {},
            'hosts_by_status': {},
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'network_ranges': self.network_ranges,
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
            'network_ranges': self.network_ranges,
            'database_stats': {
                'total_hosts': len(self.db.get_all_hosts()),
                'active_hosts': len(self.db.get_all_hosts(active_only=True))
            },
            'oui_stats': self.oui_manager.standard_oui.get_stats() if hasattr(self.oui_manager, 'standard_oui') else {},
            'nvd_stats': self.nvd_manager.get_nvd_stats() if hasattr(self.nvd_manager, 'get_nvd_stats') else {},
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

    def perform_maintenance(self):
        """Esegue operazioni di manutenzione"""
        logger.info("Avvio manutenzione database")

        # Pulisci dati vecchi
        cleanup_days = self.config.get('database', {}).get('cleanup_old_scans_days', 90)
        self.db.cleanup_old_data(cleanup_days)

        # Aggiorna database OUI se necessario
        if hasattr(self.oui_manager, 'needs_update') and self.oui_manager.needs_update():
            if hasattr(self.oui_manager, 'update_database'):
                self.oui_manager.update_database()

        # Aggiorna database NVD se necessario
        if hasattr(self.nvd_manager, 'needs_update') and self.nvd_manager.needs_update():
            if hasattr(self.nvd_manager, 'update_nvd_database'):
                self.nvd_manager.update_nvd_database()

        logger.info("Manutenzione completata")


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


def estimate_scan_time(scan_type: str, target: Union[str, List[str]]) -> str:
    """Stima il tempo di scansione per target singoli o multipli"""

    # Normalizza target
    if isinstance(target, str):
        target_list = [target]
    else:
        target_list = normalize_network_range(target)

    total_host_count = 0

    for single_target in target_list:
        # Calcola numero approssimativo di host per ogni target
        if '/' in single_target:  # CIDR
            cidr_suffix = int(single_target.split('/')[-1])
            host_count = 2 ** (32 - cidr_suffix) - 2
        elif '-' in single_target:  # Range
            start_ip = int(single_target.split('-')[0].split('.')[-1])
            end_ip = int(single_target.split('-')[1])
            host_count = end_ip - start_ip + 1
        else:  # Singolo host
            host_count = 1

        total_host_count += host_count

    # Tempo base per tipo di scansione (secondi per host)
    time_per_host = {
        'discovery': 0.5,
        'quick_scan': 5,
        'comprehensive': 30,
        'vulnerability': 20,
        'snmp': 2
    }

    base_time = time_per_host.get(scan_type, 10)
    total_seconds = total_host_count * base_time

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


# Classe di utilità per template di scansione
class ScanTemplateManager:
    """Gestore per template di scansione predefiniti con supporto multi-subnet"""

    def __init__(self, config: Dict):
        self.config = config
        self.templates = self._load_default_templates()

    def _load_default_templates(self) -> Dict[str, Dict]:
        """Carica template di scansione predefiniti"""
        return {
            'network_discovery': {
                'name': 'Network Discovery',
                'description': 'Scoperta rapida di host attivi su multiple subnet',
                'scan_type': 'discovery',
                'options': '-sn -PE -PP -PS21,22,23,25,80,113,31339',
                'estimated_time': '2-5 minuti per subnet',
                'suitable_for': ['Scoperta iniziale', 'Monitoraggio hosts', 'Multiple subnet']
            },
            'port_scan_top1000': {
                'name': 'Port Scan Top 1000',
                'description': 'Scansione delle 1000 porte più comuni su multiple subnet',
                'scan_type': 'quick_scan',
                'options': '-sS --top-ports 1000',
                'estimated_time': '5-15 minuti per subnet',
                'suitable_for': ['Analisi servizi', 'Identificazione servizi', 'Multiple subnet']
            },
            'comprehensive_scan': {
                'name': 'Scansione Completa Multi-Subnet',
                'description': 'Scansione completa con OS e service detection su tutte le subnet',
                'scan_type': 'comprehensive',
                'options': '-sS -sU -O -sV -sC --top-ports 1000',
                'estimated_time': '30-60 minuti per subnet',
                'suitable_for': ['Audit completo', 'Inventario dettagliato', 'Multiple subnet']
            },
            'vulnerability_assessment': {
                'name': 'Vulnerability Assessment Multi-Subnet',
                'description': 'Scansione focalizzata su vulnerabilità su tutte le subnet',
                'scan_type': 'vulnerability',
                'options': '-sV --script vuln,exploit',
                'estimated_time': '20-45 minuti per subnet',
                'suitable_for': ['Security audit', 'Penetration testing', 'Multiple subnet']
            },
            'snmp_enumeration': {
                'name': 'SNMP Enumeration Multi-Subnet',
                'description': 'Enumerazione servizi SNMP su tutte le subnet',
                'scan_type': 'snmp',
                'options': '-sU -p 161 --script snmp-*',
                'estimated_time': '10-20 minuti per subnet',
                'suitable_for': ['Network devices', 'Monitoring systems', 'Multiple subnet']
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