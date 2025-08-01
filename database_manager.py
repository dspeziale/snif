import sqlite3
import logging
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime
import json
from contextlib import contextmanager


class DatabaseManager:
    """
    Classe per la gestione del database SQLite del progetto AdminLTE.
    Fornisce metodi per leggere e scrivere dati con gestione automatica delle connessioni.
    """

    def __init__(self, db_path: str = 'adminlte.db', logger: Optional[logging.Logger] = None):
        """
        Inizializza il DatabaseManager.

        Args:
            db_path (str): Percorso del file database SQLite
            logger (Optional[logging.Logger]): Logger personalizzato
        """
        self.db_path = db_path
        self.logger = logger or self._setup_logger()

        # Schema delle tabelle per validazione
        self.table_schemas = {
            'menu_items': {
                'id': 'INTEGER PRIMARY KEY',
                'name': 'VARCHAR(100) NOT NULL',
                'icon': 'VARCHAR(50) NOT NULL',
                'url': 'VARCHAR(200)',
                'parent_id': 'INTEGER',
                'order_index': 'INTEGER DEFAULT 0',
                'is_active': 'BOOLEAN DEFAULT 0',
                'has_children': 'BOOLEAN DEFAULT 0',
                'badge': 'VARCHAR(20)',
                'badge_class': 'VARCHAR(100)',
                'is_header': 'BOOLEAN DEFAULT 0',
                'created_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP',
                'updated_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP'
            },
            'messages': {
                'id': 'INTEGER PRIMARY KEY',
                'sender_name': 'VARCHAR(100) NOT NULL',
                'sender_avatar': 'VARCHAR(200)',
                'message': 'TEXT NOT NULL',
                'timestamp': 'DATETIME DEFAULT CURRENT_TIMESTAMP',
                'is_read': 'BOOLEAN DEFAULT 0',
                'is_important': 'BOOLEAN DEFAULT 0',
                'created_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP'
            },
            'notifications': {
                'id': 'INTEGER PRIMARY KEY',
                'icon': 'VARCHAR(50) NOT NULL',
                'title': 'VARCHAR(200) NOT NULL',
                'message': 'TEXT',
                'time_ago': 'VARCHAR(50)',
                'url': 'VARCHAR(200)',
                'is_read': 'BOOLEAN DEFAULT 0',
                'created_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP'
            }
        }

    def _setup_logger(self) -> logging.Logger:
        """Configura il logger di default."""
        logger = logging.getLogger('DatabaseManager')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    @contextmanager
    def get_connection(self):
        """
        Context manager per la gestione delle connessioni al database.
        Garantisce la chiusura automatica delle connessioni.
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Abilita l'accesso per nome colonna
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Errore database: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def execute_query(self, query: str, params: Optional[Union[tuple, dict]] = None,
                      fetch: str = 'none') -> Union[List[Dict], Dict, None]:
        """
        Esegue una query SQL.

        Args:
            query (str): Query SQL da eseguire
            params (Optional[Union[tuple, dict]]): Parametri per la query
            fetch (str): Tipo di fetch ('all', 'one', 'none')

        Returns:
            Union[List[Dict], Dict, None]: Risultati della query
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)

                if fetch == 'all':
                    rows = cursor.fetchall()
                    return [dict(row) for row in rows]
                elif fetch == 'one':
                    row = cursor.fetchone()
                    return dict(row) if row else None
                else:
                    conn.commit()
                    return cursor.rowcount

        except Exception as e:
            self.logger.error(f"Errore nell'esecuzione della query: {e}")
            self.logger.error(f"Query: {query}")
            self.logger.error(f"Params: {params}")
            raise

    def insert(self, table: str, data: Dict[str, Any]) -> int:
        """
        Inserisce un record in una tabella.

        Args:
            table (str): Nome della tabella
            data (Dict[str, Any]): Dati da inserire

        Returns:
            int: ID del record inserito
        """
        if table not in self.table_schemas:
            raise ValueError(f"Tabella '{table}' non riconosciuta")

        # Filtra solo i campi validi per la tabella
        valid_fields = set(self.table_schemas[table].keys()) - {'id'}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}

        if not filtered_data:
            raise ValueError("Nessun dato valido da inserire")

        columns = ', '.join(filtered_data.keys())
        placeholders = ', '.join(['?' for _ in filtered_data])
        values = list(filtered_data.values())

        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, values)
                conn.commit()
                inserted_id = cursor.lastrowid

                self.logger.info(f"Record inserito in {table} con ID: {inserted_id}")
                return inserted_id

        except Exception as e:
            self.logger.error(f"Errore nell'inserimento in {table}: {e}")
            raise

    def update(self, table: str, data: Dict[str, Any], where_clause: str,
               where_params: Optional[Union[tuple, dict]] = None) -> int:
        """
        Aggiorna record in una tabella.

        Args:
            table (str): Nome della tabella
            data (Dict[str, Any]): Dati da aggiornare
            where_clause (str): Clausola WHERE
            where_params: Parametri per la clausola WHERE

        Returns:
            int: Numero di record aggiornati
        """
        if table not in self.table_schemas:
            raise ValueError(f"Tabella '{table}' non riconosciuta")

        # Filtra solo i campi validi per la tabella
        valid_fields = set(self.table_schemas[table].keys())
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}

        if not filtered_data:
            raise ValueError("Nessun dato valido da aggiornare")

        # Aggiungi updated_at se esiste nella tabella
        if 'updated_at' in valid_fields:
            filtered_data['updated_at'] = datetime.now().isoformat()

        set_clause = ', '.join([f"{k} = ?" for k in filtered_data.keys()])
        values = list(filtered_data.values())

        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"

        if where_params:
            if isinstance(where_params, (tuple, list)):
                values.extend(where_params)
            elif isinstance(where_params, dict):
                values.extend(where_params.values())

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, values)
                conn.commit()
                updated_count = cursor.rowcount

                self.logger.info(f"Aggiornati {updated_count} record in {table}")
                return updated_count

        except Exception as e:
            self.logger.error(f"Errore nell'aggiornamento di {table}: {e}")
            raise

    def delete(self, table: str, where_clause: str,
               where_params: Optional[Union[tuple, dict]] = None) -> int:
        """
        Elimina record da una tabella.

        Args:
            table (str): Nome della tabella
            where_clause (str): Clausola WHERE
            where_params: Parametri per la clausola WHERE

        Returns:
            int: Numero di record eliminati
        """
        if table not in self.table_schemas:
            raise ValueError(f"Tabella '{table}' non riconosciuta")

        query = f"DELETE FROM {table} WHERE {where_clause}"

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if where_params:
                    cursor.execute(query, where_params)
                else:
                    cursor.execute(query)
                conn.commit()
                deleted_count = cursor.rowcount

                self.logger.info(f"Eliminati {deleted_count} record da {table}")
                return deleted_count

        except Exception as e:
            self.logger.error(f"Errore nell'eliminazione da {table}: {e}")
            raise

    def select(self, table: str, columns: str = '*', where_clause: str = '',
               where_params: Optional[Union[tuple, dict]] = None,
               order_by: str = '', limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Seleziona record da una tabella.

        Args:
            table (str): Nome della tabella
            columns (str): Colonne da selezionare
            where_clause (str): Clausola WHERE opzionale
            where_params: Parametri per la clausola WHERE
            order_by (str): Clausola ORDER BY opzionale
            limit (Optional[int]): Limite di record

        Returns:
            List[Dict[str, Any]]: Lista di record
        """
        if table not in self.table_schemas:
            raise ValueError(f"Tabella '{table}' non riconosciuta")

        query = f"SELECT {columns} FROM {table}"

        if where_clause:
            query += f" WHERE {where_clause}"

        if order_by:
            query += f" ORDER BY {order_by}"

        if limit:
            query += f" LIMIT {limit}"

        return self.execute_query(query, where_params, fetch='all')

    def select_one(self, table: str, columns: str = '*', where_clause: str = '',
                   where_params: Optional[Union[tuple, dict]] = None) -> Optional[Dict[str, Any]]:
        """
        Seleziona un singolo record da una tabella.

        Returns:
            Optional[Dict[str, Any]]: Record trovato o None
        """
        results = self.select(table, columns, where_clause, where_params, limit=1)
        return results[0] if results else None

    def count(self, table: str, where_clause: str = '',
              where_params: Optional[Union[tuple, dict]] = None) -> int:
        """
        Conta i record in una tabella.

        Returns:
            int: Numero di record
        """
        if table not in self.table_schemas:
            raise ValueError(f"Tabella '{table}' non riconosciuta")

        query = f"SELECT COUNT(*) as count FROM {table}"

        if where_clause:
            query += f" WHERE {where_clause}"

        result = self.execute_query(query, where_params, fetch='one')
        return result['count'] if result else 0

    def table_exists(self, table_name: str) -> bool:
        """
        Verifica se una tabella esiste.

        Args:
            table_name (str): Nome della tabella

        Returns:
            bool: True se la tabella esiste
        """
        query = """
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name=?
        """
        result = self.execute_query(query, (table_name,), fetch='one')
        return result is not None

    def get_table_info(self, table_name: str) -> List[Dict[str, Any]]:
        """
        Ottiene informazioni sulla struttura di una tabella.

        Args:
            table_name (str): Nome della tabella

        Returns:
            List[Dict[str, Any]]: Informazioni sulle colonne
        """
        query = f"PRAGMA table_info({table_name})"
        return self.execute_query(query, fetch='all')

    def create_tables(self) -> None:
        """
        Crea tutte le tabelle definite nello schema.
        """
        for table_name, schema in self.table_schemas.items():
            if not self.table_exists(table_name):
                self._create_table(table_name, schema)
            else:
                self.logger.info(f"Tabella {table_name} già esistente")

    def _create_table(self, table_name: str, schema: Dict[str, str]) -> None:
        """
        Crea una singola tabella.

        Args:
            table_name (str): Nome della tabella
            schema (Dict[str, str]): Schema della tabella
        """
        columns_def = []
        for column, definition in schema.items():
            columns_def.append(f"{column} {definition}")

        # Aggiungi foreign key per parent_id se presente
        if table_name == 'menu_items' and 'parent_id' in schema:
            columns_def.append("FOREIGN KEY (parent_id) REFERENCES menu_items (id)")

        columns_sql = ",\n    ".join(columns_def)
        query = f"""
            CREATE TABLE {table_name} (
                {columns_sql}
            )
        """

        self.execute_query(query)
        self.logger.info(f"Tabella {table_name} creata con successo")

    def backup_database(self, backup_path: str) -> None:
        """
        Crea un backup del database.

        Args:
            backup_path (str): Percorso del file di backup
        """
        try:
            with self.get_connection() as source:
                backup = sqlite3.connect(backup_path)
                source.backup(backup)
                backup.close()

            self.logger.info(f"Backup creato: {backup_path}")

        except Exception as e:
            self.logger.error(f"Errore nel backup: {e}")
            raise

    def export_table_to_json(self, table: str, file_path: str) -> None:
        """
        Esporta una tabella in formato JSON.

        Args:
            table (str): Nome della tabella
            file_path (str): Percorso del file JSON
        """
        try:
            data = self.select(table)

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)

            self.logger.info(f"Tabella {table} esportata in {file_path}")

        except Exception as e:
            self.logger.error(f"Errore nell'esportazione: {e}")
            raise

    def get_database_stats(self) -> Dict[str, Any]:
        """
        Ottiene statistiche del database.

        Returns:
            Dict[str, Any]: Statistiche delle tabelle
        """
        stats = {
            'database_path': self.db_path,
            'tables': {}
        }

        for table in self.table_schemas.keys():
            if self.table_exists(table):
                count = self.count(table)
                stats['tables'][table] = {
                    'record_count': count,
                    'columns': list(self.table_schemas[table].keys())
                }

        return stats


# Funzioni di utilità per il progetto AdminLTE

class AdminLTEQueries:
    """
    Classe con query predefinite specifiche per il progetto AdminLTE.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def get_active_menu_items(self) -> List[Dict[str, Any]]:
        """Ottiene tutti gli elementi del menu attivi."""
        return self.db.select(
            'menu_items',
            where_clause='parent_id IS NULL',
            order_by='order_index ASC'
        )

    def get_menu_hierarchy(self) -> List[Dict[str, Any]]:
        """Ottiene la gerarchia completa del menu."""
        # Prima ottieni i menu principali
        main_items = self.db.select(
            'menu_items',
            where_clause='parent_id IS NULL',
            order_by='order_index ASC'
        )

        # Poi aggiungi i sottomenu
        for item in main_items:
            children = self.db.select(
                'menu_items',
                where_clause='parent_id = ?',
                where_params=(item['id'],),
                order_by='order_index ASC'
            )
            item['children'] = children

        return main_items

    def get_unread_messages(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Ottiene i messaggi non letti."""
        return self.db.select(
            'messages',
            where_clause='is_read = 0',
            order_by='timestamp DESC',
            limit=limit
        )

    def get_unread_notifications(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Ottiene le notifiche non lette."""
        return self.db.select(
            'notifications',
            where_clause='is_read = 0',
            order_by='created_at DESC',
            limit=limit
        )

    def mark_message_as_read(self, message_id: int) -> int:
        """Marca un messaggio come letto."""
        return self.db.update(
            'messages',
            {'is_read': 1},
            'id = ?',
            (message_id,)
        )

    def mark_notification_as_read(self, notification_id: int) -> int:
        """Marca una notifica come letta."""
        return self.db.update(
            'notifications',
            {'is_read': 1},
            'id = ?',
            (notification_id,)
        )

    def get_message_count(self) -> Dict[str, int]:
        """Ottiene il conteggio dei messaggi."""
        total = self.db.count('messages')
        unread = self.db.count('messages', 'is_read = 0')

        return {
            'total': total,
            'unread': unread,
            'read': total - unread
        }

    def get_notification_count(self) -> Dict[str, int]:
        """Ottiene il conteggio delle notifiche."""
        total = self.db.count('notifications')
        unread = self.db.count('notifications', 'is_read = 0')

        return {
            'total': total,
            'unread': unread,
            'read': total - unread
        }


# Esempio di utilizzo
if __name__ == "__main__":
    # Inizializza il database manager
    db = DatabaseManager('adminlte.db')

    # Crea le tabelle se non esistono
    db.create_tables()

    # Inizializza le query AdminLTE
    adminlte = AdminLTEQueries(db)

    # Esempi di utilizzo
    try:
        # Inserisce un nuovo messaggio
        message_id = db.insert('messages', {
            'sender_name': 'Test User',
            'sender_avatar': '/static/img/user.jpg',
            'message': 'Messaggio di test',
            'is_important': True
        })
        print(f"Messaggio inserito con ID: {message_id}")

        # Ottiene i messaggi non letti
        unread_messages = adminlte.get_unread_messages()
        print(f"Messaggi non letti: {len(unread_messages)}")

        # Ottiene statistiche del database
        stats = db.get_database_stats()
        print("Statistiche database:", json.dumps(stats, indent=2))

    except Exception as e:
        print(f"Errore: {e}")