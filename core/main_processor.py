#!/usr/bin/env python3
"""
Main Processor - Processo principale che coordina tutte le operazioni
Legge i file XML e coordina tutti i parser specializzati
"""

import os
import sys
import logging
from typing import Dict, List
from pathlib import Path

# Import delle classi modulari
from database_manager import DatabaseManager
from xml_parser import XMLParser
from software_parser import SoftwareParser
from vulnerability_parser import VulnerabilityParser
from device_classifier import DeviceClassifier

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('../logs/nmap_processor.log', mode='a', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)


class MainProcessor:
    """Classe principale che coordina tutto il processo di parsing"""

    def __init__(self, db_path: str = "../data/snmp_scan_results.db",
                 xml_directory: str = "../xml"):
        """Inizializza il processore principale"""
        self.db_path = db_path
        self.xml_directory = xml_directory

        # Assicurati che le directory esistano
        os.makedirs("../data", exist_ok=True)
        os.makedirs("../logs", exist_ok=True)
        os.makedirs("../reports", exist_ok=True)

        # Inizializza i componenti
        self.db_manager = DatabaseManager(db_path)
        self.xml_parser = None
        self.software_parser = None
        self.vulnerability_parser = None
        self.device_classifier = None

    def initialize_components(self):
        """Inizializza tutti i componenti con le connessioni al database"""
        try:
            # Connetti al database e crea tabelle
            self.db_manager.connect()
            self.db_manager.create_tables()

            # Inizializza i parser specializzati
            self.xml_parser = XMLParser(self.db_manager)
            self.software_parser = SoftwareParser(self.db_manager)
            self.vulnerability_parser = VulnerabilityParser(self.db_manager)
            self.device_classifier = DeviceClassifier(self.db_manager)

            logger.info("Tutti i componenti inizializzati con successo")

        except Exception as e:
            logger.error(f"Errore nell'inizializzazione dei componenti: {e}")
            raise

    def get_xml_files(self) -> List[str]:
        """Ottiene la lista di tutti i file XML da processare"""
        try:
            xml_files = []
            xml_path = Path(self.xml_directory)

            if xml_path.exists():
                xml_files = [str(f) for f in xml_path.glob("*.xml")]
                xml_files.sort()  # Ordina per consistenza

            logger.info(f"Trovati {len(xml_files)} file XML in {self.xml_directory}")
            return xml_files

        except Exception as e:
            logger.error(f"Errore nella ricerca dei file XML: {e}")
            return []

    def process_single_xml_file(self, xml_file_path: str) -> bool:
        """Processa un singolo file XML con tutti i parser"""
        try:
            logger.info(f"Inizio processamento: {xml_file_path}")

            # 1. Parse principale (host, porte, servizi, OS, etc.)
            success = self.xml_parser.parse_xml_file(xml_file_path)
            if not success:
                logger.error(f"Errore nel parsing principale di {xml_file_path}")
                return False

            # 2. Parse software e processi
            logger.info(f"Parsing software e processi da {xml_file_path}")
            self.software_parser.parse_software_and_processes(xml_file_path)

            # 3. Parse vulnerabilità
            logger.info(f"Parsing vulnerabilità da {xml_file_path}")
            self.vulnerability_parser.parse_vulnerabilities(xml_file_path)

            # 4. Discovery hostname aggiuntivo
            logger.info(f"Discovery hostname da {xml_file_path}")
            self.xml_parser.process_hostname_discovery(xml_file_path)

            logger.info(f"Completato processamento: {xml_file_path}")
            return True

        except Exception as e:
            logger.error(f"Errore nel processamento di {xml_file_path}: {e}")
            return False

    def process_all_xml_files(self) -> Dict:
        """Processa tutti i file XML nella directory"""
        xml_files = self.get_xml_files()

        if not xml_files:
            logger.warning(f"Nessun file XML trovato in {self.xml_directory}")
            return {"processed": 0, "errors": 0, "files": []}

        results = {
            "processed": 0,
            "errors": 0,
            "files": [],
            "error_files": []
        }

        logger.info(f"Inizio processamento di {len(xml_files)} file XML")

        for xml_file in xml_files:
            try:
                success = self.process_single_xml_file(xml_file)

                if success:
                    results["processed"] += 1
                    results["files"].append(xml_file)
                else:
                    results["errors"] += 1
                    results["error_files"].append(xml_file)

            except Exception as e:
                logger.error(f"Errore critico nel processamento di {xml_file}: {e}")
                results["errors"] += 1
                results["error_files"].append(xml_file)

        logger.info(f"Processamento completato: {results['processed']} successi, {results['errors']} errori")

        # 7. Classificazione automatica dispositivi (dopo aver processato tutti i file)
        if results['processed'] > 0:
            logger.info("Avvio classificazione automatica dispositivi...")
            self.device_classifier.classify_all_devices()

        return results

    def generate_comprehensive_report(self) -> Dict:
        """Genera un report completo di tutti i dati"""
        try:
            logger.info("Generazione report completo...")

            # Report base dal database manager
            report = self.db_manager.generate_summary_report()

            # Aggiungi statistiche vulnerabilità
            vuln_summary = self.vulnerability_parser.get_vulnerability_summary()
            report['vulnerabilities_detail'] = vuln_summary

            # Aggiungi statistiche classificazione dispositivi
            classification_summary = self.device_classifier.get_classification_summary()
            report['device_classification'] = classification_summary

            # Statistiche software (top 10 più comuni)
            self.db_manager.cursor.execute('''
                SELECT software_name, COUNT(*) as count
                FROM installed_software 
                GROUP BY software_name 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            report['top_software'] = self.db_manager.cursor.fetchall()

            # Statistiche processi (top 10 più comuni)
            self.db_manager.cursor.execute('''
                SELECT process_name, COUNT(*) as count
                FROM running_processes 
                GROUP BY process_name 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            report['top_processes'] = self.db_manager.cursor.fetchall()

            # Host con più servizi
            self.db_manager.cursor.execute('''
                SELECT h.ip_address, h.hostname, COUNT(DISTINCT p.port_number) as open_ports
                FROM hosts h
                JOIN ports p ON h.ip_address = p.ip_address
                WHERE p.state = 'open'
                GROUP BY h.ip_address, h.hostname
                ORDER BY open_ports DESC
                LIMIT 10
            ''')
            report['hosts_most_services'] = self.db_manager.cursor.fetchall()

            # Servizi più comuni
            self.db_manager.cursor.execute('''
                SELECT s.service_name, COUNT(*) as count
                FROM services s
                JOIN ports p ON s.ip_address = p.ip_address AND s.port_number = p.port_number
                WHERE p.state = 'open' AND s.service_name IS NOT NULL
                GROUP BY s.service_name
                ORDER BY count DESC
                LIMIT 10
            ''')
            report['top_services'] = self.db_manager.cursor.fetchall()

            return report

        except Exception as e:
            logger.error(f"Errore nella generazione del report: {e}")
            return {}

    def print_detailed_report(self, report: Dict):
        """Stampa un report dettagliato a console"""
        print("\n" + "=" * 80)
        print("REPORT COMPLETO SCANSIONE NETWORK - NMAP XML PARSER")
        print("=" * 80)

        # Statistiche generali
        print(f"\n📊 STATISTICHE GENERALI:")
        print(f"   Host totali trovati: {report.get('total_hosts', 0)}")
        print(f"   Host attivi: {report.get('active_hosts', 0)}")
        print(f"   Host con hostname: {report.get('hosts_with_hostname', 0)}")
        print(f"   Host con hostname multipli: {report.get('hosts_with_multiple_hostnames', 0)}")
        print(f"   Porte aperte totali: {report.get('open_ports', 0)}")

        # Vulnerabilità
        vuln_detail = report.get('vulnerabilities_detail', {})
        total_vulns = vuln_detail.get('total_vulnerabilities', 0)
        print(f"\n🚨 VULNERABILITÀ:")
        print(f"   Vulnerabilità totali: {total_vulns}")

        if vuln_detail.get('by_severity'):
            print("   Distribuzione per severità:")
            for severity, count in vuln_detail['by_severity'].items():
                print(f"     {severity}: {count}")

        # Software e processi
        print(f"\n💿 SOFTWARE E PROCESSI:")
        print(f"   Software installato: {report.get('installed_software', 0)}")
        print(f"   Processi in esecuzione: {report.get('running_processes', 0)}")

        # Top software
        if report.get('top_software'):
            print(f"\n   Top 5 software più comuni:")
            for software, count in report['top_software'][:5]:
                print(f"     {software}: {count} installazioni")

        # Top servizi
        if report.get('top_services'):
            print(f"\n🌐 SERVIZI DI RETE:")
            print(f"   Top 5 servizi più comuni:")
            for service, count in report['top_services'][:5]:
                print(f"     {service}: {count} istanze")

        # Classificazione dispositivi
        device_classification = report.get('device_classification', {})
        print(f"\n🔍 CLASSIFICAZIONE DISPOSITIVI:")
        if device_classification.get('by_type'):
            print("   Distribuzione per tipo:")
            for device_type, count in device_classification['by_type'].items():
                print(f"     {device_type}: {count}")

        print(f"   Alta confidenza (≥0.7): {device_classification.get('high_confidence', 0)}")
        print(f"   Bassa confidenza (<0.5): {device_classification.get('low_confidence', 0)}")

        if device_classification.get('top_vendors'):
            print(f"\n   Top 5 vendor (da OUI):")
            for vendor, count in list(device_classification['top_vendors'].items())[:5]:
                print(f"     {vendor}: {count}")

        # Top porte
        if report.get('top_ports'):
            print(f"\n   Top 5 porte più comuni:")
            for port, count in report['top_ports']:
                print(f"     Porta {port}: {count} host")

        # Host con più servizi
        if report.get('hosts_most_services'):
            print(f"\n   Host con più servizi esposti:")
            for ip, hostname, port_count in report['hosts_most_services'][:5]:
                hostname_str = f" ({hostname})" if hostname else ""
                print(f"     {ip}{hostname_str}: {port_count} porte aperte")

        # Vendor
        if report.get('vendors'):
            print(f"\n🏭 VENDOR HARDWARE:")
            for vendor, count in report['vendors'][:5]:
                print(f"     {vendor}: {count} dispositivi")

        print(f"\n💾 DATABASE:")
        print(f"   Database salvato in: {self.db_path}")
        print(f"   Log salvati in: ../logs/nmap_processor.log")

        print("\n" + "=" * 80)

    def export_reports(self):
        """Esporta report in diversi formati"""
        try:
            logger.info("Esportazione report...")

            # Report vulnerabilità
            self.vulnerability_parser.export_vulnerabilities_report()

            # Report classificazione dispositivi
            self.device_classifier.export_classification_report()

            # Report CSV con host e servizi principali
            self._export_hosts_csv()

            # Report JSON completo
            self._export_json_report()

            logger.info("Report esportati con successo in ../reports/")

        except Exception as e:
            logger.error(f"Errore nell'esportazione dei report: {e}")

    def _export_hosts_csv(self):
        """Esporta lista host in formato CSV"""
        try:
            import csv

            output_file = "../reports/hosts_summary.csv"

            # Query per dati host principali con classificazione
            self.db_manager.cursor.execute('''
                SELECT 
                    h.ip_address,
                    h.hostname,
                    h.status,
                    h.vendor,
                    COUNT(DISTINCT p.port_number) as open_ports,
                    GROUP_CONCAT(DISTINCT s.service_name) as services,
                    COUNT(DISTINCT v.vuln_id) as vulnerabilities,
                    dc.device_type,
                    dc.device_subtype
                FROM hosts h
                LEFT JOIN ports p ON h.ip_address = p.ip_address AND p.state = 'open'
                LEFT JOIN services s ON h.ip_address = s.ip_address
                LEFT JOIN vulnerabilities v ON h.ip_address = v.ip_address
                LEFT JOIN device_classification dc ON h.ip_address = dc.ip_address
                GROUP BY h.ip_address
                ORDER BY h.ip_address
            ''')

            results = self.db_manager.cursor.fetchall()

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)

                # Header
                writer.writerow(['IP Address', 'Hostname', 'Status', 'Vendor',
                                 'Open Ports', 'Services', 'Vulnerabilities', 'Device Type', 'Device Subtype'])

                # Dati
                for row in results:
                    writer.writerow(row)

            logger.info(f"Report CSV esportato in: {output_file}")

        except Exception as e:
            logger.error(f"Errore esportazione CSV: {e}")

    def _export_json_report(self):
        """Esporta report completo in formato JSON"""
        try:
            import json

            output_file = "../reports/complete_report.json"
            report = self.generate_comprehensive_report()

            # Converti datetime e altri tipi non JSON-serializable
            json_report = self._convert_for_json(report)

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, ensure_ascii=False)

            logger.info(f"Report JSON esportato in: {output_file}")

        except Exception as e:
            logger.error(f"Errore esportazione JSON: {e}")

    def _convert_for_json(self, obj):
        """Converte oggetti per serializzazione JSON"""
        if isinstance(obj, dict):
            return {k: self._convert_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_for_json(v) for v in obj]
        elif hasattr(obj, 'isoformat'):  # datetime
            return obj.isoformat()
        else:
            return obj

    def cleanup(self):
        """Pulizia e chiusura connessioni"""
        try:
            if self.db_manager:
                self.db_manager.close()
            logger.info("Cleanup completato")
        except Exception as e:
            logger.error(f"Errore durante cleanup: {e}")

    def run_complete_analysis(self) -> bool:
        """Esegue l'analisi completa di tutti i file XML"""
        try:
            logger.info("🚀 Avvio analisi completa NMAP XML Parser")

            # 1. Inizializzazione
            self.initialize_components()

            # 2. Processamento file XML
            process_results = self.process_all_xml_files()

            if process_results['processed'] == 0:
                logger.error("Nessun file XML processato con successo")
                return False

            # 3. Generazione report
            report = self.generate_comprehensive_report()

            # 4. Stampa report a console
            self.print_detailed_report(report)

            # 5. Esportazione report
            self.export_reports()

            # 6. Statistiche finali
            print(f"\n✅ ANALISI COMPLETATA CON SUCCESSO")
            print(f"   File processati: {process_results['processed']}")
            print(f"   File con errori: {process_results['errors']}")
            print(f"   Database: {self.db_path}")
            print(f"   Report salvati in: ../reports/")

            return True

        except Exception as e:
            logger.error(f"Errore durante l'analisi completa: {e}")
            return False

        finally:
            self.cleanup()


def main():
    """Funzione principale"""
    try:
        # Configurazione percorsi
        db_path = "../data/snmp_scan_results.db"
        xml_directory = "../xml"

        # Verifica che la directory XML esista
        if not os.path.exists(xml_directory):
            print(f"❌ Errore: Directory {xml_directory} non trovata")
            print(f"   Assicurati che i file XML di nmap siano in {xml_directory}")
            sys.exit(1)

        # Crea il processore principale ed esegui l'analisi
        processor = MainProcessor(db_path, xml_directory)
        success = processor.run_complete_analysis()

        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        logger.info("Analisi interrotta dall'utente")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Errore critico: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()