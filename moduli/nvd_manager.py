"""
Gestore per il database NVD (National Vulnerability Database)
Scarica e mantiene aggiornato il database delle vulnerabilità CVE
"""
import requests
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging
import sqlite3

logger = logging.getLogger(__name__)


class NVDManager:
    def __init__(self, db_manager, config: Dict):
        self.db = db_manager
        self.config = config
        self.api_key = config.get('nvd', {}).get('api_key')
        self.base_url = config.get('nvd', {}).get('base_url', 'https://services.nvd.nist.gov/rest/json/cves/2.0')
        self.rate_limit = config.get('nvd', {}).get('rate_limit_seconds', 6)
        self.update_interval = config.get('nvd', {}).get('update_interval_minutes', 1440)  # 24 ore default

        if not self.api_key or self.api_key == "YOUR_NVD_API_KEY_HERE":
            logger.warning("NVD API Key non configurata - funzionalità limitate")
            self.api_key = None

    def needs_update(self) -> bool:
        """Controlla se il database NVD ha bisogno di aggiornamento"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT MAX(last_updated) as last_update 
                FROM cve_database
            """)
            row = cursor.fetchone()

            if not row or not row['last_update']:
                return True

            last_update = datetime.fromisoformat(row['last_update'])
            update_threshold = datetime.now() - timedelta(minutes=self.update_interval)

            return last_update < update_threshold

    def update_nvd_database(self, days_back: int = 7) -> Dict[str, Any]:
        """Aggiorna il database NVD scaricando CVE recenti"""
        logger.info("Inizio aggiornamento database NVD")
        start_time = time.time()

        if not self.api_key:
            return {
                'success': False,
                'error': 'API Key NVD non configurata',
                'duration_seconds': time.time() - start_time
            }

        try:
            # Calcola date per la ricerca
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)

            # Scarica CVE recenti
            cve_data = self._fetch_recent_cves(start_date, end_date)

            # Inserisci nel database
            inserted_count = self._insert_cve_data(cve_data)

            duration = time.time() - start_time

            result = {
                'success': True,
                'cves_processed': len(cve_data),
                'cves_inserted': inserted_count,
                'duration_seconds': round(duration, 2),
                'date_range': f"{start_date.date()} to {end_date.date()}",
                'last_updated': datetime.now().isoformat()
            }

            logger.info(f"Aggiornamento NVD completato: {inserted_count} CVE in {duration:.2f}s")
            return result

        except Exception as e:
            logger.error(f"Errore aggiornamento NVD database: {e}")
            return {
                'success': False,
                'error': str(e),
                'duration_seconds': time.time() - start_time
            }

    def _fetch_recent_cves(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Scarica CVE recenti dall'API NVD"""
        all_cves = []
        start_index = 0
        results_per_page = 2000  # Max consentito da NVD

        headers = {'apiKey': self.api_key} if self.api_key else {}

        while True:
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }

            logger.info(f"Scaricamento CVE da indice {start_index}")

            try:
                response = requests.get(self.base_url, params=params, headers=headers, timeout=30)
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                if not vulnerabilities:
                    break

                all_cves.extend(vulnerabilities)

                # Controlla se ci sono più risultati
                total_results = data.get('totalResults', 0)
                if start_index + results_per_page >= total_results:
                    break

                start_index += results_per_page

                # Rate limiting
                time.sleep(self.rate_limit)

            except requests.RequestException as e:
                logger.error(f"Errore scaricamento CVE da NVD: {e}")
                break

        logger.info(f"Scaricati {len(all_cves)} CVE da NVD")
        return all_cves

    def _insert_cve_data(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """Inserisce/aggiorna i dati CVE nel database"""
        inserted_count = 0

        with self.db.get_connection() as conn:
            for vuln_data in vulnerabilities:
                try:
                    cve_data = self._parse_cve_data(vuln_data)
                    if cve_data:
                        conn.execute("""
                            INSERT OR REPLACE INTO cve_database (
                                cve_id, description, cvss_v2_score, cvss_v2_vector,
                                cvss_v3_score, cvss_v3_vector, severity, published_date,
                                modified_date, cpe_list, references, exploit_available,
                                last_updated
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """, (
                            cve_data['cve_id'],
                            cve_data['description'],
                            cve_data['cvss_v2_score'],
                            cve_data['cvss_v2_vector'],
                            cve_data['cvss_v3_score'],
                            cve_data['cvss_v3_vector'],
                            cve_data['severity'],
                            cve_data['published_date'],
                            cve_data['modified_date'],
                            json.dumps(cve_data['cpe_list']),
                            json.dumps(cve_data['references']),
                            cve_data['exploit_available']
                        ))
                        inserted_count += 1

                except Exception as e:
                    logger.warning(f"Errore inserimento CVE {vuln_data}: {e}")

            conn.commit()

        return inserted_count

    def _parse_cve_data(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parsa i dati CVE dall'API NVD"""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id')

            if not cve_id:
                return None

            # Descrizioni
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break

            # Date
            published_date = cve.get('published')
            modified_date = cve.get('lastModified')

            # CVSS Scores
            metrics = cve.get('metrics', {})
            cvss_v2_score = None
            cvss_v2_vector = None
            cvss_v3_score = None
            cvss_v3_vector = None
            severity = 'unknown'

            # CVSS v3.x
            cvss_v3_data = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
            if cvss_v3_data:
                cvss_v3 = cvss_v3_data[0].get('cvssData', {})
                cvss_v3_score = cvss_v3.get('baseScore')
                cvss_v3_vector = cvss_v3.get('vectorString')
                severity = cvss_v3.get('baseSeverity', '').lower()

            # CVSS v2
            cvss_v2_data = metrics.get('cvssMetricV2', [])
            if cvss_v2_data:
                cvss_v2 = cvss_v2_data[0].get('cvssData', {})
                cvss_v2_score = cvss_v2.get('baseScore')
                cvss_v2_vector = cvss_v2.get('vectorString')

                # Se non abbiamo severity da v3, calcolala da v2
                if severity == 'unknown' and cvss_v2_score:
                    severity = self._calculate_severity_from_score(cvss_v2_score)

            # CPE (Common Platform Enumeration)
            configurations = cve.get('configurations', [])
            cpe_list = []
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe_uri = cpe_match.get('criteria')
                        if cpe_uri:
                            cpe_list.append(cpe_uri)

            # References
            references = []
            for ref in cve.get('references', []):
                ref_data = {
                    'url': ref.get('url'),
                    'source': ref.get('source'),
                    'tags': ref.get('tags', [])
                }
                references.append(ref_data)

            # Controlla se ci sono exploit disponibili
            exploit_available = self._check_exploit_availability(references)

            return {
                'cve_id': cve_id,
                'description': description[:2000],  # Limita lunghezza
                'cvss_v2_score': cvss_v2_score,
                'cvss_v2_vector': cvss_v2_vector,
                'cvss_v3_score': cvss_v3_score,
                'cvss_v3_vector': cvss_v3_vector,
                'severity': severity,
                'published_date': published_date,
                'modified_date': modified_date,
                'cpe_list': cpe_list,
                'references': references,
                'exploit_available': exploit_available
            }

        except Exception as e:
            logger.error(f"Errore parsing CVE data: {e}")
            return None

    def _calculate_severity_from_score(self, score: float) -> str:
        """Calcola severity basata su CVSS score"""
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        else:
            return 'low'

    def _check_exploit_availability(self, references: List[Dict]) -> bool:
        """Controlla se ci sono riferimenti a exploit"""
        exploit_indicators = [
            'exploit', 'poc', 'proof of concept', 'metasploit',
            'exploit-db', 'exploitdb', 'github.com/exploit'
        ]

        for ref in references:
            url = ref.get('url', '').lower()
            tags = [tag.lower() for tag in ref.get('tags', [])]

            if any(indicator in url for indicator in exploit_indicators):
                return True

            if 'exploit' in tags or 'proof-of-concept' in tags:
                return True

        return False

    def get_cve_info(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Recupera informazioni su un CVE specifico"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM cve_database WHERE cve_id = ?
            """, (cve_id,))

            row = cursor.fetchone()
            if row:
                cve_data = dict(row)
                # Parse JSON fields
                cve_data['cpe_list'] = json.loads(cve_data.get('cpe_list', '[]'))
                cve_data['references'] = json.loads(cve_data.get('references', '[]'))
                return cve_data

            return None

    def search_cves(self, search_term: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Cerca CVE per termine"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT cve_id, description, cvss_v3_score, cvss_v2_score, 
                       severity, published_date, exploit_available
                FROM cve_database
                WHERE description LIKE ? OR cve_id LIKE ?
                ORDER BY 
                    CASE WHEN cvss_v3_score IS NOT NULL THEN cvss_v3_score 
                         ELSE cvss_v2_score END DESC
                LIMIT ?
            """, (f'%{search_term}%', f'%{search_term}%', limit))

            return [dict(row) for row in cursor.fetchall()]

    def get_high_severity_cves(self, days: int = 30, min_score: float = 7.0) -> List[Dict[str, Any]]:
        """Recupera CVE ad alta severità degli ultimi giorni"""
        cutoff_date = datetime.now() - timedelta(days=days)

        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT cve_id, description, cvss_v3_score, cvss_v2_score,
                       severity, published_date, exploit_available
                FROM cve_database
                WHERE (cvss_v3_score >= ? OR cvss_v2_score >= ?)
                  AND published_date >= ?
                ORDER BY 
                    CASE WHEN cvss_v3_score IS NOT NULL THEN cvss_v3_score 
                         ELSE cvss_v2_score END DESC
            """, (min_score, min_score, cutoff_date.isoformat()))

            return [dict(row) for row in cursor.fetchall()]

    def get_cves_with_exploits(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Recupera CVE con exploit disponibili"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT cve_id, description, cvss_v3_score, cvss_v2_score,
                       severity, published_date
                FROM cve_database
                WHERE exploit_available = 1
                ORDER BY 
                    CASE WHEN cvss_v3_score IS NOT NULL THEN cvss_v3_score 
                         ELSE cvss_v2_score END DESC
                LIMIT ?
            """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def get_cves_by_cpe(self, cpe_pattern: str) -> List[Dict[str, Any]]:
        """Trova CVE che affettano un CPE specifico"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT cve_id, description, cvss_v3_score, cvss_v2_score,
                       severity, published_date, cpe_list
                FROM cve_database
                WHERE cpe_list LIKE ?
                ORDER BY 
                    CASE WHEN cvss_v3_score IS NOT NULL THEN cvss_v3_score 
                         ELSE cvss_v2_score END DESC
            """, (f'%{cpe_pattern}%',))

            results = []
            for row in cursor.fetchall():
                cve_data = dict(row)
                cpe_list = json.loads(cve_data.get('cpe_list', '[]'))

                # Verifica match più preciso
                if any(cpe_pattern.lower() in cpe.lower() for cpe in cpe_list):
                    cve_data['cpe_list'] = cpe_list
                    results.append(cve_data)

            return results

    def get_nvd_stats(self) -> Dict[str, Any]:
        """Statistiche del database NVD"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_cves,
                    COUNT(CASE WHEN exploit_available = 1 THEN 1 END) as cves_with_exploits,
                    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_cves,
                    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_cves,
                    COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_cves,
                    COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_cves,
                    MIN(published_date) as oldest_cve,
                    MAX(published_date) as newest_cve,
                    AVG(CASE WHEN cvss_v3_score IS NOT NULL THEN cvss_v3_score 
                             ELSE cvss_v2_score END) as avg_cvss_score
                FROM cve_database
            """)

            stats = dict(cursor.fetchone())

            # Top CVE per severità degli ultimi 30 giorni
            cutoff_date = datetime.now() - timedelta(days=30)
            cursor = conn.execute("""
                SELECT cve_id, 
                    CASE WHEN cvss_v3_score IS NOT NULL THEN cvss_v3_score 
                         ELSE cvss_v2_score END as score
                FROM cve_database
                WHERE published_date >= ?
                ORDER BY score DESC
                LIMIT 10
            """, (cutoff_date.isoformat(),))

            stats['recent_high_cves'] = [dict(row) for row in cursor.fetchall()]

            return stats

    def fetch_specific_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Scarica un CVE specifico dall'API NVD"""
        if not self.api_key:
            logger.warning("API Key NVD necessaria per scaricare CVE specifici")
            return None

        try:
            headers = {'apiKey': self.api_key}
            params = {'cveId': cve_id}

            response = requests.get(self.base_url, params=params, headers=headers, timeout=30)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            if vulnerabilities:
                cve_data = self._parse_cve_data(vulnerabilities[0])
                if cve_data:
                    # Inserisci nel database
                    self._insert_cve_data([vulnerabilities[0]])
                    return cve_data

            return None

        except Exception as e:
            logger.error(f"Errore scaricamento CVE {cve_id}: {e}")
            return None

    def cleanup_old_cves(self, days: int = 365):
        """Rimuove CVE più vecchi di X giorni (per gestire spazio)"""
        cutoff_date = datetime.now() - timedelta(days=days)

        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM cve_database
                WHERE published_date < ?
                  AND severity NOT IN ('critical', 'high')
                  AND exploit_available = 0
            """, (cutoff_date.isoformat(),))

            deleted_count = cursor.rowcount
            conn.commit()

            logger.info(f"Rimossi {deleted_count} CVE vecchi dal database")
            return deleted_count

    def export_cve_data(self, output_file: str, severity_filter: Optional[str] = None):
        """Esporta dati CVE in formato JSON"""
        with self.db.get_connection() as conn:
            query = "SELECT * FROM cve_database"
            params = []

            if severity_filter:
                query += " WHERE severity = ?"
                params.append(severity_filter)

            query += " ORDER BY published_date DESC"

            cursor = conn.execute(query, params)

            cves = []
            for row in cursor.fetchall():
                cve_data = dict(row)
                cve_data['cpe_list'] = json.loads(cve_data.get('cpe_list', '[]'))
                cve_data['references'] = json.loads(cve_data.get('references', '[]'))
                cves.append(cve_data)

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(cves, f, indent=2, default=str)

            logger.info(f"Esportati {len(cves)} CVE in {output_file}")


class VulnerabilityMatcher:
    """Classe per fare match tra servizi scansionati e vulnerabilità note"""

    def __init__(self, nvd_manager: NVDManager):
        self.nvd = nvd_manager

    def find_vulnerabilities_for_service(self, service_name: str, service_version: str = None) -> List[Dict[str, Any]]:
        """Trova vulnerabilità per un servizio specifico"""
        search_terms = [service_name]

        if service_version:
            search_terms.append(f"{service_name} {service_version}")

        vulnerabilities = []
        for term in search_terms:
            cves = self.nvd.search_cves(term, limit=20)
            vulnerabilities.extend(cves)

        # Rimuovi duplicati
        seen_cves = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            if vuln['cve_id'] not in seen_cves:
                seen_cves.add(vuln['cve_id'])
                unique_vulns.append(vuln)

        return unique_vulns

    def match_host_vulnerabilities(self, host_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Trova vulnerabilità per tutti i servizi di un host"""
        all_vulnerabilities = []

        for port in host_ports:
            service_name = port.get('service_name')
            service_version = port.get('service_version')

            if service_name:
                vulns = self.find_vulnerabilities_for_service(service_name, service_version)

                for vuln in vulns:
                    vuln['matched_port'] = port.get('port')
                    vuln['matched_service'] = service_name
                    vuln['matched_version'] = service_version
                    all_vulnerabilities.append(vuln)

        return all_vulnerabilities