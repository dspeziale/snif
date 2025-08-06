"""
Menu Database Implementation with SQLite
Implementazione del sistema di menu con database SQLite
"""

import sqlite3
import json
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# ==================== SCHEMA DATABASE ====================

SCHEMA_SQL = """
-- Tabella principale per i menu items
CREATE TABLE IF NOT EXISTS menu_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER,
    type VARCHAR(50) NOT NULL, -- 'header', 'item'
    text VARCHAR(255) NOT NULL,
    icon VARCHAR(100),
    url VARCHAR(500),
    active BOOLEAN DEFAULT 0,
    badge_text VARCHAR(50),
    badge_color VARCHAR(50),
    position INTEGER DEFAULT 0, -- per ordinamento
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (parent_id) REFERENCES menu_items(id) ON DELETE CASCADE
);

-- Indici per ottimizzare le query
CREATE INDEX IF NOT EXISTS idx_menu_parent ON menu_items(parent_id);
CREATE INDEX IF NOT EXISTS idx_menu_position ON menu_items(position);
CREATE INDEX IF NOT EXISTS idx_menu_type ON menu_items(type);

-- Tabella per i permessi sui menu (opzionale)
CREATE TABLE IF NOT EXISTS menu_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    menu_item_id INTEGER NOT NULL,
    role VARCHAR(100) NOT NULL,
    can_view BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (menu_item_id) REFERENCES menu_items(id) ON DELETE CASCADE
);

-- Tabella per le traduzioni (opzionale)
CREATE TABLE IF NOT EXISTS menu_translations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    menu_item_id INTEGER NOT NULL,
    language_code VARCHAR(10) NOT NULL,
    text VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (menu_item_id) REFERENCES menu_items(id) ON DELETE CASCADE,
    UNIQUE(menu_item_id, language_code)
);
"""


# ==================== DATA CLASSES ====================

@dataclass
class MenuItem:
    """Rappresenta un singolo elemento del menu"""
    id: Optional[int] = None
    parent_id: Optional[int] = None
    type: str = 'item'
    text: str = ''
    icon: Optional[str] = None
    url: Optional[str] = None
    active: bool = False
    badge_text: Optional[str] = None
    badge_color: Optional[str] = None
    position: int = 0
    children: List['MenuItem'] = None

    def __post_init__(self):
        if self.children is None:
            self.children = []

    def to_dict(self, include_children=True):
        """Converte l'oggetto in dizionario per JSON"""
        data = {
            'id': self.id,
            'type': self.type,
            'text': self.text,
            'icon': self.icon,
            'url': self.url,
            'active': self.active,
            'position': self.position
        }

        # Aggiungi campi opzionali solo se presenti
        if self.badge_text:
            data['badge_text'] = self.badge_text
        if self.badge_color:
            data['badge_color'] = self.badge_color

        # Aggiungi children se presenti e richiesti
        if include_children and self.children:
            data['children'] = [child.to_dict() for child in self.children]

        # Rimuovi campi None
        return {k: v for k, v in data.items() if v is not None}


# ==================== DATABASE MANAGER ====================

class MenuDatabase:
    """Gestisce tutte le operazioni del database per i menu"""

    def __init__(self, db_path: str = 'menu.db'):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        """Crea una connessione al database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Per avere risultati come dizionari
        return conn

    def init_database(self):
        """Inizializza il database con lo schema"""
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    def insert_menu_item(self, item: MenuItem) -> int:
        """Inserisce un nuovo menu item nel database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO menu_items (parent_id, type, text, icon, url, active, 
                                       badge_text, badge_color, position)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (item.parent_id, item.type, item.text, item.icon, item.url,
                  item.active, item.badge_text, item.badge_color, item.position))
            conn.commit()
            return cursor.lastrowid

    def update_menu_item(self, item: MenuItem) -> bool:
        """Aggiorna un menu item esistente"""
        if not item.id:
            return False

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE menu_items 
                SET parent_id=?, type=?, text=?, icon=?, url=?, active=?,
                    badge_text=?, badge_color=?, position=?, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
            """, (item.parent_id, item.type, item.text, item.icon, item.url,
                  item.active, item.badge_text, item.badge_color, item.position, item.id))
            conn.commit()
            return cursor.rowcount > 0

    def delete_menu_item(self, item_id: int) -> bool:
        """Elimina un menu item e tutti i suoi figli"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM menu_items WHERE id=?", (item_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_menu_item(self, item_id: int) -> Optional[MenuItem]:
        """Recupera un singolo menu item"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM menu_items WHERE id=?", (item_id,))
            row = cursor.fetchone()
            if row:
                return self._row_to_menu_item(row)
            return None

    def get_menu_tree(self, parent_id: Optional[int] = None) -> List[MenuItem]:
        """Recupera l'albero completo del menu a partire da un parent_id"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Query ricorsiva per ottenere tutto l'albero
            if parent_id is None:
                cursor.execute("""
                    SELECT * FROM menu_items 
                    WHERE parent_id IS NULL 
                    ORDER BY position, id
                """)
            else:
                cursor.execute("""
                    SELECT * FROM menu_items 
                    WHERE parent_id = ? 
                    ORDER BY position, id
                """, (parent_id,))

            items = []
            for row in cursor.fetchall():
                item = self._row_to_menu_item(row)
                # Carica ricorsivamente i figli
                item.children = self.get_menu_tree(item.id)
                items.append(item)

            return items

    def get_flat_menu_list(self) -> List[MenuItem]:
        """Recupera tutti i menu items in formato piatto (senza gerarchia)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM menu_items ORDER BY position, id")
            return [self._row_to_menu_item(row) for row in cursor.fetchall()]

    def _row_to_menu_item(self, row) -> MenuItem:
        """Converte una riga del database in oggetto MenuItem"""
        return MenuItem(
            id=row['id'],
            parent_id=row['parent_id'],
            type=row['type'],
            text=row['text'],
            icon=row['icon'],
            url=row['url'],
            active=bool(row['active']),
            badge_text=row['badge_text'],
            badge_color=row['badge_color'],
            position=row['position']
        )

    def import_from_json(self, json_data: Dict[str, Any]):
        """Importa menu da struttura JSON esistente"""
        menu_items = json_data.get('menu_items', [])
        self._import_items_recursive(menu_items, None, 0)

    def _import_items_recursive(self, items: List[Dict], parent_id: Optional[int], base_position: int):
        """Importa ricorsivamente gli items del menu"""
        for idx, item_data in enumerate(items):
            # Crea il menu item
            menu_item = MenuItem(
                parent_id=parent_id,
                type=item_data.get('type', 'item'),
                text=item_data.get('text', ''),
                icon=item_data.get('icon'),
                url=item_data.get('url'),
                active=item_data.get('active', False),
                badge_text=item_data.get('badge_text'),
                badge_color=item_data.get('badge_color'),
                position=base_position + idx
            )

            # Inserisci nel database
            item_id = self.insert_menu_item(menu_item)

            # Se ci sono figli, importali ricorsivamente
            if 'children' in item_data:
                self._import_items_recursive(item_data['children'], item_id, 0)

    def export_to_json(self) -> Dict[str, Any]:
        """Esporta l'intero menu in formato JSON compatibile con la struttura esistente"""
        menu_tree = self.get_menu_tree()
        return {
            'menu_items': [item.to_dict() for item in menu_tree]
        }

    def search_menu_items(self, search_text: str) -> List[MenuItem]:
        """Cerca menu items per testo"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM menu_items 
                WHERE text LIKE ? OR url LIKE ?
                ORDER BY position, id
            """, (f'%{search_text}%', f'%{search_text}%'))
            return [self._row_to_menu_item(row) for row in cursor.fetchall()]

    def reorder_items(self, item_ids: List[int], parent_id: Optional[int] = None):
        """Riordina gli items secondo l'ordine specificato"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for position, item_id in enumerate(item_ids):
                cursor.execute("""
                    UPDATE menu_items 
                    SET position = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND parent_id IS ?
                """, (position, item_id, parent_id))
            conn.commit()


# ==================== MIGRATION HELPER ====================

def migrate_from_json_file(json_file_path: str, db_path: str = 'menu.db'):
    """
    Migra i dati da un file JSON esistente al database SQLite

    Args:
        json_file_path: Path del file menu.json esistente
        db_path: Path del database SQLite da creare/usare
    """
    # Leggi il file JSON
    with open(json_file_path, 'r', encoding='utf-8') as f:
        json_data = json.load(f)

    # Crea il database e importa i dati
    db = MenuDatabase(db_path)

    # Pulisci eventuali dati esistenti
    with db.get_connection() as conn:
        conn.execute("DELETE FROM menu_items")
        conn.commit()

    # Importa i nuovi dati
    db.import_from_json(json_data)

    print(f"Migrazione completata! Dati importati da {json_file_path} a {db_path}")

    # Verifica
    exported = db.export_to_json()
    print(f"Totale menu items importati: {len(db.get_flat_menu_list())}")

    return db


# ==================== ESEMPIO DI UTILIZZO ====================

if __name__ == "__main__":
    # Esempio di migrazione dal file JSON esistente
    db = migrate_from_json_file('menu.json', 'menu.db')

    # Esempio di query
    print("\n=== Menu Tree ===")
    menu_tree = db.get_menu_tree()
    for item in menu_tree:
        print(f"- {item.text} ({item.type})")
        for child in item.children:
            print(f"  - {child.text}")

    # Esempio di ricerca
    print("\n=== Ricerca 'Dashboard' ===")
    results = db.search_menu_items('Dashboard')
    for item in results:
        print(f"Trovato: {item.text} - {item.url}")