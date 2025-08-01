"""
Gestore per il database OUI (Organizationally Unique Identifier)
Scarica e mantiene aggiornato il database dei vendor MAC address
"""
import requests
import re
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
import logging
import time

logger = logging.getLogger(__name__)


class OUIManager:
    def __init__(self, db_manager, config: Dict):
        self.db = db_manager
        self.config = config
        self.oui_url = config.get('oui', {}).get('url', 'http://standards-oui.ieee.org/oui/oui.txt')
        self.update_interval = config.get('oui', {}).get('update_interval_minutes', 10080)  # 7 giorni default

    def needs_update(self) -> bool:
        """Controlla se il database OUI ha bisogno di aggiornamento"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT MAX(last_updated) as last_update 
                FROM oui_vendors
            """)
            row = cursor.fetchone()

            if not row or not row['last_update']:
                return True

            last_update = datetime.fromisoformat(row['last_update'])
            update_threshold = datetime.now() - timedelta(minutes=self.update_interval)

            return last_update < update_threshold

    def update_oui_database(self) -> Dict[str, Any]:
        """Aggiorna il database OUI scaricando i dati più recenti"""
        logger.info("Inizio aggiornamento database OUI")
        start_time = time.time()

        try:
            # Scarica il file OUI
            logger.info(f"Scaricamento OUI data da {self.oui_url}")
            response = requests.get(self.oui_url, timeout=30)
            response.raise_for_status()

            oui_data = response.text

            # Parsa e inserisce i dati
            parsed_entries = self._parse_oui_data(oui_data)
            inserted_count = self._insert_oui_entries(parsed_entries)

            duration = time.time() - start_time

            result = {
                'success': True,
                'entries_processed': len(parsed_entries),
                'entries_inserted': inserted_count,
                'duration_seconds': round(duration, 2),
                'last_updated': datetime.now().isoformat()
            }

            logger.info(f"Aggiornamento OUI completato: {inserted_count} entries in {duration:.2f}s")
            return result

        except requests.RequestException as e:
            logger.error(f"Errore scaricamento OUI data: {e}")
            return {
                'success': False,
                'error': f"Errore rete: {str(e)}",
                'duration_seconds': time.time() - start_time
            }
        except Exception as e:
            logger.error(f"Errore aggiornamento OUI database: {e}")
            return {
                'success': False,
                'error': str(e),
                'duration_seconds': time.time() - start_time
            }

    def _parse_oui_data(self, oui_text: str) -> List[Dict[str, str]]:
        """Parsa il file OUI testuale dell'IEEE"""
        entries = []
        current_entry = None

        lines = oui_text.split('\n')

        for line in lines:
            line = line.strip()

            if not line:
                continue

            # Linea con OUI assignment (formato: XX-XX-XX   (hex)    Vendor Name)
            oui_match = re.match(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$', line)
            if oui_match:
                if current_entry:
                    entries.append(current_entry)

                oui = oui_match.group(1).replace('-', '')
                vendor_name = oui_match.group(2).strip()

                current_entry = {
                    'oui': oui,
                    'vendor_name': vendor_name,
                    'vendor_address': ''
                }
                continue

            # Linea con base-16 (skip, è duplicata info)
            if '(base 16)' in line:
                continue

            # Linee di indirizzo del vendor
            if current_entry and line and not line.startswith('Copyright'):
                # Accumula l'indirizzo
                if current_entry['vendor_address']:
                    current_entry['vendor_address'] += ', '
                current_entry['vendor_address'] += line

        # Aggiungi l'ultimo entry
        if current_entry:
            entries.append(current_entry)

        logger.info(f"Parsati {len(entries)} entries OUI")
        return entries

    def _insert_oui_entries(self, entries: List[Dict[str, str]]) -> int:
        """Inserisce/aggiorna i dati OUI nel database"""
        inserted_count = 0

        with self.db.get_connection() as conn:
            # Pulisci tabella esistente per aggiornamento completo
            conn.execute("DELETE FROM oui_vendors")

            # Inserisci tutti i nuovi dati
            for entry in entries:
                try:
                    conn.execute("""
                        INSERT INTO oui_vendors (oui, vendor_name, vendor_address, last_updated)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        entry['oui'],
                        entry['vendor_name'][:200],  # Limit length
                        entry['vendor_address'][:500]  # Limit length
                    ))
                    inserted_count += 1
                except sqlite3.Error as e:
                    logger.warning(f"Errore inserimento OUI {entry['oui']}: {e}")

            conn.commit()

        return inserted_count

    def get_vendor_by_mac(self, mac_address: str) -> Optional[str]:
        """Recupera il vendor dal MAC address"""
        if not mac_address or len(mac_address) < 8:
            return None

        # Normalizza MAC address
        mac_clean = mac_address.upper().replace(':', '').replace('-', '').replace('.', '')

        if len(mac_clean) < 6:
            return None

        oui = mac_clean[:6]

        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT vendor_name FROM oui_vendors WHERE oui = ?
            """, (oui,))

            row = cursor.fetchone()
            return row['vendor_name'] if row else None

    def search_vendors(self, search_term: str, limit: int = 50) -> List[Dict[str, str]]:
        """Cerca vendor per nome"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT oui, vendor_name, vendor_address
                FROM oui_vendors
                WHERE vendor_name LIKE ?
                ORDER BY vendor_name
                LIMIT ?
            """, (f'%{search_term}%', limit))

            return [dict(row) for row in cursor.fetchall()]

    def get_vendor_info(self, oui: str) -> Optional[Dict[str, str]]:
        """Recupera informazioni complete del vendor per OUI"""
        oui_clean = oui.upper().replace(':', '').replace('-', '')

        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT oui, vendor_name, vendor_address, last_updated
                FROM oui_vendors
                WHERE oui = ?
            """, (oui_clean,))

            row = cursor.fetchone()
            return dict(row) if row else None

    def get_stats(self) -> Dict[str, Any]:
        """Statistiche del database OUI"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_entries,
                    COUNT(DISTINCT vendor_name) as unique_vendors,
                    MIN(last_updated) as oldest_update,
                    MAX(last_updated) as newest_update
                FROM oui_vendors
            """)

            row = cursor.fetchone()

            if row:
                stats = dict(row)

                # Top vendors by OUI count
                cursor = conn.execute("""
                    SELECT vendor_name, COUNT(*) as oui_count
                    FROM oui_vendors
                    GROUP BY vendor_name
                    ORDER BY oui_count DESC
                    LIMIT 10
                """)

                stats['top_vendors'] = [dict(row) for row in cursor.fetchall()]

                return stats

            return {}

    def cleanup_old_entries(self, days: int = 30):
        """Rimuove entries OUI più vecchi di X giorni (cleanup)"""
        cutoff_date = datetime.now() - timedelta(days=days)

        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM oui_vendors
                WHERE last_updated < ?
            """, (cutoff_date.isoformat(),))

            deleted_count = cursor.rowcount
            conn.commit()

            logger.info(f"Rimossi {deleted_count} entries OUI più vecchi di {days} giorni")
            return deleted_count

    def export_oui_data(self, output_file: str):
        """Esporta i dati OUI in formato CSV"""
        import csv

        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT oui, vendor_name, vendor_address, last_updated
                FROM oui_vendors
                ORDER BY oui
            """)

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['OUI', 'Vendor Name', 'Vendor Address', 'Last Updated'])

                for row in cursor:
                    writer.writerow([row['oui'], row['vendor_name'],
                                     row['vendor_address'], row['last_updated']])

        logger.info(f"Dati OUI esportati in {output_file}")

    def import_custom_oui(self, custom_mappings: List[Dict[str, str]]):
        """Importa mappings OUI personalizzati"""
        inserted_count = 0

        with self.db.get_connection() as conn:
            for mapping in custom_mappings:
                try:
                    conn.execute("""
                        INSERT OR REPLACE INTO oui_vendors (oui, vendor_name, vendor_address, last_updated)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        mapping['oui'].upper().replace(':', '').replace('-', ''),
                        mapping.get('vendor_name', ''),
                        mapping.get('vendor_address', '')
                    ))
                    inserted_count += 1
                except sqlite3.Error as e:
                    logger.error(f"Errore inserimento custom OUI {mapping}: {e}")

            conn.commit()

        logger.info(f"Importati {inserted_count} custom OUI mappings")
        return inserted_count

    def get_mac_info(self, mac_address: str) -> Dict[str, Any]:
        """Restituisce informazioni complete su un MAC address"""
        vendor = self.get_vendor_by_mac(mac_address)
        mac_clean = mac_address.upper().replace(':', '').replace('-', '').replace('.', '')

        info = {
            'mac_address': mac_address,
            'mac_normalized': mac_clean,
            'oui': mac_clean[:6] if len(mac_clean) >= 6 else None,
            'vendor': vendor,
            'is_local': self._is_local_mac(mac_address),
            'is_multicast': self._is_multicast_mac(mac_address),
            'is_unicast': self._is_unicast_mac(mac_address)
        }

        # Informazioni aggiuntive se vendor trovato
        if vendor:
            oui_info = self.get_vendor_info(mac_clean[:6])
            if oui_info:
                info.update({
                    'vendor_address': oui_info.get('vendor_address'),
                    'oui_last_updated': oui_info.get('last_updated')
                })

        return info

    def _is_local_mac(self, mac_address: str) -> bool:
        """Verifica se è un MAC address locale (bit U/L = 1)"""
        mac_clean = mac_address.replace(':', '').replace('-', '').replace('.', '')
        if len(mac_clean) < 2:
            return False

        try:
            first_octet = int(mac_clean[:2], 16)
            return bool(first_octet & 0x02)  # Bit 1 = Local
        except ValueError:
            return False

    def _is_multicast_mac(self, mac_address: str) -> bool:
        """Verifica se è un MAC address multicast (bit I/G = 1)"""
        mac_clean = mac_address.replace(':', '').replace('-', '').replace('.', '')
        if len(mac_clean) < 2:
            return False

        try:
            first_octet = int(mac_clean[:2], 16)
            return bool(first_octet & 0x01)  # Bit 0 = Individual/Group
        except ValueError:
            return False

    def _is_unicast_mac(self, mac_address: str) -> bool:
        """Verifica se è un MAC address unicast"""
        return not self._is_multicast_mac(mac_address)


class CustomOUIManager:
    """Gestore per OUI personalizzati e override locali"""

    def __init__(self, db_manager):
        self.db = db_manager
        self._init_custom_table()

    def _init_custom_table(self):
        """Inizializza la tabella per OUI personalizzati"""
        with self.db.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS custom_oui (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    oui TEXT UNIQUE NOT NULL,
                    vendor_name TEXT NOT NULL,
                    vendor_address TEXT,
                    notes TEXT,
                    priority INTEGER DEFAULT 100,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_custom_oui_lookup ON custom_oui(oui)")
            conn.commit()

    def add_custom_mapping(self, oui: str, vendor_name: str, vendor_address: str = '',
                           notes: str = '', priority: int = 100) -> bool:
        """Aggiunge un mapping OUI personalizzato"""
        oui_clean = oui.upper().replace(':', '').replace('-', '')

        try:
            with self.db.get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO custom_oui 
                    (oui, vendor_name, vendor_address, notes, priority, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (oui_clean, vendor_name, vendor_address, notes, priority))

                conn.commit()
                logger.info(f"Aggiunto custom OUI mapping: {oui_clean} -> {vendor_name}")
                return True

        except sqlite3.Error as e:
            logger.error(f"Errore aggiunta custom OUI mapping: {e}")
            return False

    def get_custom_vendor(self, mac_address: str) -> Optional[str]:
        """Recupera vendor da mapping personalizzato (ha priorità su OUI standard)"""
        mac_clean = mac_address.upper().replace(':', '').replace('-', '').replace('.', '')

        if len(mac_clean) < 6:
            return None

        oui = mac_clean[:6]

        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT vendor_name FROM custom_oui
                WHERE oui = ?
                ORDER BY priority DESC
                LIMIT 1
            """, (oui,))

            row = cursor.fetchone()
            return row['vendor_name'] if row else None

    def list_custom_mappings(self) -> List[Dict[str, Any]]:
        """Lista tutti i mapping personalizzati"""
        with self.db.get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM custom_oui
                ORDER BY priority DESC, vendor_name
            """)

            return [dict(row) for row in cursor.fetchall()]

    def delete_custom_mapping(self, oui: str) -> bool:
        """Rimuove un mapping personalizzato"""
        oui_clean = oui.upper().replace(':', '').replace('-', '')

        try:
            with self.db.get_connection() as conn:
                cursor = conn.execute("DELETE FROM custom_oui WHERE oui = ?", (oui_clean,))
                deleted = cursor.rowcount > 0
                conn.commit()

                if deleted:
                    logger.info(f"Rimosso custom OUI mapping: {oui_clean}")

                return deleted

        except sqlite3.Error as e:
            logger.error(f"Errore rimozione custom OUI mapping: {e}")
            return False


class EnhancedOUIManager:
    """Versione migliorata che combina OUI standard e personalizzati"""

    def __init__(self, db_manager, config: Dict):
        self.standard_oui = OUIManager(db_manager, config)
        self.custom_oui = CustomOUIManager(db_manager)

    def needs_update(self) -> bool:
        """
        Verifica se il database OUI ha bisogno di essere aggiornato.
        Controlla l'età del file OUI scaricato confrontandolo con una soglia.

        Returns:
            bool: True se necessita aggiornamento, False altrimenti
        """
        import os
        from datetime import datetime, timedelta

        try:
            # Percorso del file OUI (adatta questo percorso secondo la tua struttura)
            oui_file_path = getattr(self, 'oui_file_path', 'data/oui.txt')

            # Se il file non esiste, necessita aggiornamento
            if not os.path.exists(oui_file_path):
                return True

            # Ottieni la data di ultima modifica del file
            last_modified = datetime.fromtimestamp(os.path.getmtime(oui_file_path))

            # Soglia di aggiornamento (esempio: 30 giorni)
            update_threshold = timedelta(days=30)

            # Controlla se il file è più vecchio della soglia
            if datetime.now() - last_modified > update_threshold:
                return True

            return False

        except Exception as e:
            # In caso di errore, assume che sia necessario l'aggiornamento
            print(f"Errore nel controllo aggiornamento OUI: {e}")
            return True

    def get_vendor_by_mac(self, mac_address: str) -> Optional[str]:
        """Recupera vendor con priorità ai mapping personalizzati"""
        # Prima prova con mapping personalizzati
        custom_vendor = self.custom_oui.get_custom_vendor(mac_address)
        if custom_vendor:
            return custom_vendor

        # Poi con database OUI standard
        return self.standard_oui.get_vendor_by_mac(mac_address)

    def update_database(self) -> Dict[str, Any]:
        """Aggiorna il database OUI se necessario"""
        if self.standard_oui.needs_update():
            return self.standard_oui.update_oui_database()
        else:
            return {
                'success': True,
                'message': 'Database OUI già aggiornato',
                'last_update': 'N/A'
            }

    def get_comprehensive_mac_info(self, mac_address: str) -> Dict[str, Any]:
        """Informazioni complete su MAC address includendo custom mappings"""
        info = self.standard_oui.get_mac_info(mac_address)

        # Controlla se c'è un override personalizzato
        custom_vendor = self.custom_oui.get_custom_vendor(mac_address)
        if custom_vendor:
            info['vendor'] = custom_vendor
            info['custom_mapping'] = True
        else:
            info['custom_mapping'] = False

        return info