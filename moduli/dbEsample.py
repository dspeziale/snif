#!/usr/bin/env python3
"""
Esempi di utilizzo della classe DatabaseManager per il progetto AdminLTE.
Questo file mostra come integrare il DatabaseManager con il progetto Flask esistente.
"""

from database_manager import DatabaseManager, AdminLTEQueries
import json
from datetime import datetime


def setup_database():
    """
    Inizializza il database e crea le tabelle se necessario.
    """
    print("=== SETUP DATABASE ===")

    # Inizializza il database manager
    db = DatabaseManager('../instance/adminlte.db')

    # Crea le tabelle se non esistono
    db.create_tables()

    # Mostra statistiche
    stats = db.get_database_stats()
    print(json.dumps(stats, indent=2))

    return db


def populate_sample_data(db: DatabaseManager):
    """
    Popola il database con dati di esempio.
    """
    print("\n=== POPOLAMENTO DATI DI ESEMPIO ===")

    # Inserisce elementi del menu
    menu_items = [
        {
            'name': 'Dashboard',
            'icon': 'bi bi-speedometer',
            'url': '#',
            'order_index': 1,
            'is_active': True,
            'has_children': True
        },
        {
            'name': 'Utenti',
            'icon': 'bi bi-people',
            'url': '/users',
            'order_index': 2,
            'is_active': False,
            'has_children': False
        },
        {
            'name': 'Impostazioni',
            'icon': 'bi bi-gear',
            'url': '/settings',
            'order_index': 3,
            'is_active': False,
            'has_children': False
        }
    ]

    for item in menu_items:
        try:
            item_id = db.insert('menu_items', item)
            print(f"Inserito menu item: {item['name']} (ID: {item_id})")
        except Exception as e:
            print(f"Errore inserimento menu {item['name']}: {e}")

    # Inserisce messaggi di esempio
    messages = [
        {
            'sender_name': 'John Doe',
            'sender_avatar': '/static/img/user1.jpg',
            'message': 'Hai ricevuto una nuova notifica importante.',
            'is_important': True,
            'is_read': False
        },
        {
            'sender_name': 'Jane Smith',
            'sender_avatar': '/static/img/user2.jpg',
            'message': 'Il report mensile è pronto per la revisione.',
            'is_important': False,
            'is_read': False
        },
        {
            'sender_name': 'Admin',
            'sender_avatar': '/static/img/admin.jpg',
            'message': 'Manutenzione programmata per domani alle 02:00.',
            'is_important': True,
            'is_read': True
        }
    ]

    for msg in messages:
        try:
            msg_id = db.insert('messages', msg)
            print(f"Inserito messaggio da: {msg['sender_name']} (ID: {msg_id})")
        except Exception as e:
            print(f"Errore inserimento messaggio: {e}")

    # Inserisce notifiche di esempio
    notifications = [
        {
            'icon': 'bi bi-envelope me-2',
            'title': '3 nuovi messaggi',
            'time_ago': '2 mins',
            'is_read': False
        },
        {
            'icon': 'bi bi-people-fill me-2',
            'title': '5 richieste di amicizia',
            'time_ago': '10 mins',
            'is_read': False
        },
        {
            'icon': 'bi bi-file-earmark-fill me-2',
            'title': '2 nuovi report',
            'time_ago': '1 hour',
            'is_read': True
        }
    ]

    for notif in notifications:
        try:
            notif_id = db.insert('notifications', notif)
            print(f"Inserita notifica: {notif['title']} (ID: {notif_id})")
        except Exception as e:
            print(f"Errore inserimento notifica: {e}")


def query_examples(db: DatabaseManager):
    """
    Esempi di query utilizzando il DatabaseManager.
    """
    print("\n=== ESEMPI DI QUERY ===")

    # Inizializza le query AdminLTE
    adminlte = AdminLTEQueries(db)

    # 1. Ottiene tutti gli elementi del menu
    print("\n1. Tutti gli elementi del menu:")
    menu_items = db.select('menu_items', order_by='order_index ASC')
    for item in menu_items:
        print(f"  - {item['name']} ({item['icon']})")

    # 2. Ottiene solo i messaggi non letti
    print("\n2. Messaggi non letti:")
    unread_messages = adminlte.get_unread_messages()
    for msg in unread_messages:
        print(f"  - {msg['sender_name']}: {msg['message'][:50]}...")

    # 3. Conta i messaggi per stato
    print("\n3. Conteggio messaggi:")
    message_counts = adminlte.get_message_count()
    print(f"  - Totali: {message_counts['total']}")
    print(f"  - Non letti: {message_counts['unread']}")
    print(f"  - Letti: {message_counts['read']}")

    # 4. Ottiene notifiche non lette
    print("\n4. Notifiche non lette:")
    unread_notifications = adminlte.get_unread_notifications()
    for notif in unread_notifications:
        print(f"  - {notif['title']} ({notif['time_ago']})")

    # 5. Query personalizzata con JOIN (simulato)
    print("\n5. Menu items con badge:")
    menu_with_badge = db.select(
        'menu_items',
        columns='name, badge, badge_class',
        where_clause='badge IS NOT NULL'
    )
    for item in menu_with_badge:
        print(f"  - {item['name']}: {item['badge']} ({item['badge_class']})")


def update_examples(db: DatabaseManager):
    """
    Esempi di aggiornamento dati.
    """
    print("\n=== ESEMPI DI AGGIORNAMENTO ===")

    adminlte = AdminLTEQueries(db)

    # 1. Marca tutti i messaggi come letti
    print("\n1. Marcando tutti i messaggi come letti...")
    updated = db.update(
        'messages',
        {'is_read': 1},
        'is_read = 0'
    )
    print(f"Aggiornati {updated} messaggi")

    # 2. Aggiorna un elemento del menu specifico
    print("\n2. Aggiornando elemento menu Dashboard...")
    updated = db.update(
        'menu_items',
        {
            'badge': '5',
            'badge_class': 'nav-badge badge text-bg-primary me-3'
        },
        'name = ?',
        ('Dashboard',)
    )
    print(f"Aggiornati {updated} elementi del menu")

    # 3. Aggiunge un nuovo submenu
    print("\n3. Aggiungendo submenu...")
    # Prima trova l'ID del menu padre
    dashboard = db.select_one('menu_items', where_clause='name = ?', where_params=('Dashboard',))
    if dashboard:
        submenu_id = db.insert('menu_items', {
            'name': 'Dashboard v2',
            'icon': 'bi bi-circle',
            'url': '/dashboard-v2',
            'parent_id': dashboard['id'],
            'order_index': 1
        })
        print(f"Submenu inserito con ID: {submenu_id}")


def advanced_queries(db: DatabaseManager):
    """
    Esempi di query avanzate.
    """
    print("\n=== QUERY AVANZATE ===")

    # 1. Query con aggregazione
    print("\n1. Statistiche messaggi per mittente:")
    query = """
        SELECT sender_name, 
               COUNT(*) as total_messages,
               SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) as unread_count,
               MAX(timestamp) as last_message
        FROM messages 
        GROUP BY sender_name
        ORDER BY total_messages DESC
    """
    results = db.execute_query(query, fetch='all')
    for row in results:
        print(f"  - {row['sender_name']}: {row['total_messages']} totali, "
              f"{row['unread_count']} non letti")

    # 2. Query con subquery
    print("\n2. Menu items con più di 0 children:")
    query = """
        SELECT m1.name, m1.icon,
               (SELECT COUNT(*) FROM menu_items m2 WHERE m2.parent_id = m1.id) as children_count
        FROM menu_items m1
        WHERE m1.parent_id IS NULL
    """
    results = db.execute_query(query, fetch='all')
    for row in results:
        print(f"  - {row['name']}: {row['children_count']} children")

    # 3. Query con date
    print("\n3. Messaggi delle ultime 24 ore:")
    query = """
        SELECT sender_name, message, timestamp
        FROM messages
        WHERE datetime(timestamp) >= datetime('now', '-1 day')
        ORDER BY timestamp DESC
    """
    results = db.execute_query(query, fetch='all')
    for row in results:
        print(f"  - {row['sender_name']}: {row['message'][:40]}... ({row['timestamp']})")


def maintenance_operations(db: DatabaseManager):
    """
    Operazioni di manutenzione del database.
    """
    print("\n=== OPERAZIONI DI MANUTENZIONE ===")

    # 1. Backup del database
    print("\n1. Creando backup...")
    backup_filename = f"../backup/adminlte_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    try:
        db.backup_database(backup_filename)
        print(f"Backup creato: {backup_filename}")
    except Exception as e:
        print(f"Errore backup: {e}")

    # 2. Esporta tabelle in JSON
    print("\n2. Esportando tabelle in JSON...")
    for table in ['menu_items', 'messages', 'notifications']:
        try:
            filename = f"../backup/{table}_{datetime.now().strftime('%Y%m%d')}.json"
            db.export_table_to_json(table, filename)
            print(f"Tabella {table} esportata in {filename}")
        except Exception as e:
            print(f"Errore esportazione {table}: {e}")

    # 3. Ottieni informazioni sulla struttura
    print("\n3. Struttura tabelle:")
    for table in db.table_schemas.keys():
        if db.table_exists(table):
            info = db.get_table_info(table)
            print(f"\nTabella: {table}")
            for col in info:
                print(f"  - {col['name']}: {col['type']} "
                      f"{'(NOT NULL)' if col['notnull'] else '(NULL)'}")


def integration_with_flask():
    """
    Esempio di integrazione con Flask.
    """
    print("\n=== INTEGRAZIONE CON FLASK ===")

    flask_code = '''
# Nel tuo app.py, puoi integrare così:

from database_manager import DatabaseManager, AdminLTEQueries
from flask import Flask, jsonify, request

app = Flask(__name__)

# Inizializza il database manager globalmente
db_manager = DatabaseManager('adminlte.db')
adminlte_queries = AdminLTEQueries(db_manager)

@app.route('/api/messages/unread')
def get_unread_messages():
    """API endpoint per ottenere messaggi non letti."""
    try:
        messages = adminlte_queries.get_unread_messages(limit=10)
        return jsonify({
            'success': True,
            'data': messages,
            'count': len(messages)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/messages/<int:message_id>/read', methods=['POST'])
def mark_message_read(message_id):
    """API endpoint per marcare un messaggio come letto."""
    try:
        updated = adminlte_queries.mark_message_as_read(message_id)
        if updated > 0:
            return jsonify({
                'success': True,
                'message': 'Messaggio marcato come letto'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Messaggio non trovato'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats')
def get_database_stats():
    """API endpoint per ottenere statistiche del database."""
    try:
        stats = db_manager.get_database_stats()
        message_counts = adminlte_queries.get_message_count()
        notification_counts = adminlte_queries.get_notification_count()

        return jsonify({
            'success': True,
            'data': {
                'database': stats,
                'messages': message_counts,
                'notifications': notification_counts
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    '''

    print(flask_code)


def main():
    """
    Funzione principale che esegue tutti gli esempi.
    """
    print("🚀 ESEMPI DatabaseManager per AdminLTE")
    print("=" * 50)

    # 1. Setup del database
    db = setup_database()

    # 2. Popola con dati di esempio (solo se le tabelle sono vuote)
    if db.count('menu_items') == 0:
        populate_sample_data(db)
    else:
        print("\n⚠️  Database già popolato, saltando inserimento dati di esempio")

    # 3. Esempi di query
    query_examples(db)

    # 4. Esempi di aggiornamento
    update_examples(db)

    # 5. Query avanzate
    advanced_queries(db)

    # 6. Operazioni di manutenzione
    maintenance_operations(db)

    # 7. Integrazione con Flask
    integration_with_flask()

    print("\n✅ Tutti gli esempi completati!")
    print("\nPer utilizzare nel tuo progetto Flask:")
    print("1. Copia database_manager.py nella tua directory del progetto")
    print("2. Importa le classi necessarie")
    print("3. Inizializza DatabaseManager con il percorso del tuo database")
    print("4. Utilizza i metodi per le operazioni CRUD")


if __name__ == "__main__":
    main()