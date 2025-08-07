# scanner/cache_manager.py
import requests
import os
import sqlite3
from datetime import datetime, timedelta
import json
import re


class CacheManager:
    """Gestisce la cache per OUI e NVD"""

    def __init__(self, db_manager):
        self.db_manager = db_manager

    def get_vendor_from_mac(self, mac_address):
        """Ottiene vendor dal MAC address usando cache OUI"""
        if not mac_address or len(mac_address) < 6:
            return None

        # Estrae i primi 3 bytes (6 caratteri hex)
        oui = mac_address.replace(':', '').replace('-', '').upper()[:6]

        # Controlla cache
        cached = self._get_cached_value('oui', oui)
        if cached:
            return cached

        # Se non in cache, aggiorna OUI e riprova
        if self._should_update_oui():
            self._update_oui_cache()
            cached = self._get_cached_value('oui', oui)
            if cached:
                return cached

        return 'Unknown'

    def get_cve_info(self, cve_id):
        """Ottiene informazioni CVE da cache NVD"""
        cached = self._get_cached_value('nvd', cve_id)
        if cached:
            return json.loads(cached)

        # Se non in cache, prova a recuperare da NVD
        cve_info = self._fetch_cve_from_nvd(cve_id)
        if cve_info:
            self._cache_value('nvd', cve_id, json.dumps(cve_info),
                              datetime.now() + timedelta(days=30))

        return cve_info

    def _get_cached_value(self, cache_type, key):
        """Ottiene valore dalla cache"""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT cache_value FROM cache 
            WHERE cache_type = ? AND cache_key = ? 
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        ''', (cache_type, key))

        result = cursor.fetchone()
        conn.close()

        return result['cache_value'] if result else None

    def _cache_value(self, cache_type, key, value, expires_at=None):
        """Salva valore in cache"""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO cache 
            (cache_type, cache_key, cache_value, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (cache_type, key, value, expires_at))

        conn.commit()
        conn.close()

    def _should_update_oui(self):
        """Controlla se è necessario aggiornare la cache OUI"""
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT MAX(created_at) as last_update 
            FROM cache 
            WHERE cache_type = 'oui_meta'
        ''')

        result = cursor.fetchone()
        conn.close()

        if not result or not result['last_update']:
            return True

        last_update = datetime.fromisoformat(result['last_update'])
        return datetime.now() - last_update > timedelta(days=30)

    def _update_oui_cache(self):
        """Aggiorna la cache OUI scaricando da IEEE"""
        try:
            print("Aggiornamento cache OUI...")
            response = requests.get(
                'http://standards-oui.ieee.org/oui/oui.txt',
                timeout=30
            )
            response.raise_for_status()

            # Pulisce cache OUI esistente
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cache WHERE cache_type = 'oui'")

            # Parse del file OUI
            lines = response.text.split('\n')
            count = 0

            for line in lines:
                if '(hex)' in line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        oui = parts[0].replace('-', '').strip()
                        vendor = parts[2].strip()

                        if len(oui) == 6 and vendor:
                            self._cache_value('oui', oui, vendor,
                                              datetime.now() + timedelta(days=60))
                            count += 1

            # Segna aggiornamento
            self._cache_value('oui_meta', 'last_update',
                              datetime.now().isoformat(),
                              datetime.now() + timedelta(days=30))

            conn.commit()
            conn.close()
            print(f"Cache OUI aggiornata: {count} entries")

        except Exception as e:
            print(f"Errore aggiornamento OUI: {e}")

    def _fetch_cve_from_nvd(self, cve_id):
        """Recupera informazioni CVE da NVD"""
        try:
            # Utilizza la nuova API NVD 2.0
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'cveId': cve_id
            }

            headers = {
                'Accept': 'application/json'
            }

            response = requests.get(url, params=params, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    cve_item = data['vulnerabilities'][0]['cve']

                    # Estrae informazioni rilevanti
                    cve_info = {
                        'id': cve_id,
                        'description': '',
                        'severity': 'Unknown',
                        'score': 0.0,
                        'published_date': '',
                        'modified_date': ''
                    }

                    # Descrizione
                    if 'descriptions' in cve_item:
                        for desc in cve_item['descriptions']:
                            if desc.get('lang') == 'en':
                                cve_info['description'] = desc.get('value', '')
                                break

                    # Score CVSS
                    if 'metrics' in cve_item:
                        # Prova prima CVSS v3
                        if 'cvssMetricV31' in cve_item['metrics']:
                            cvss_data = cve_item['metrics']['cvssMetricV31'][0]['cvssData']
                            cve_info['score'] = cvss_data.get('baseScore', 0.0)
                            cve_info['severity'] = cvss_data.get('baseSeverity', 'Unknown')
                        elif 'cvssMetricV30' in cve_item['metrics']:
                            cvss_data = cve_item['metrics']['cvssMetricV30'][0]['cvssData']
                            cve_info['score'] = cvss_data.get('baseScore', 0.0)
                            cve_info['severity'] = cvss_data.get('baseSeverity', 'Unknown')
                        elif 'cvssMetricV2' in cve_item['metrics']:
                            cvss_data = cve_item['metrics']['cvssMetricV2'][0]['cvssData']
                            cve_info['score'] = cvss_data.get('baseScore', 0.0)
                            # CVSS v2 non ha baseSeverity, calcoliamolo
                            score = cvss_data.get('baseScore', 0.0)
                            if score >= 9.0:
                                cve_info['severity'] = 'CRITICAL'
                            elif score >= 7.0:
                                cve_info['severity'] = 'HIGH'
                            elif score >= 4.0:
                                cve_info['severity'] = 'MEDIUM'
                            else:
                                cve_info['severity'] = 'LOW'

                    # Date
                    if 'published' in cve_item:
                        cve_info['published_date'] = cve_item['published']
                    if 'lastModified' in cve_item:
                        cve_info['modified_date'] = cve_item['lastModified']

                    return cve_info

        except Exception as e:
            print(f"Errore recupero CVE {cve_id}: {e}")

        return None

    def force_update_all(self):
        """Forza aggiornamento di tutte le cache"""
        try:
            self._update_oui_cache()
            print("Cache aggiornate con successo")
        except Exception as e:
            print(f"Errore aggiornamento cache: {e}")
            raise