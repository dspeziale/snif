"""
Configurazione e inizializzazione del database SQLite
"""
import os
from pathlib import Path
from flask import Flask
from models import db


def init_database(app: Flask) -> None:
    """
    Inizializza il database SQLite nella directory instance

    Args:
        app: Istanza dell'applicazione Flask
    """
    # Configurazione del database
    instance_path = Path(app.instance_path)
    instance_path.mkdir(exist_ok=True)

    db_path = instance_path / 'adminlte.db'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    # Inizializza SQLAlchemy
    db.init_app(app)

    # Crea le tabelle se non esistono
    with app.app_context():
        db.create_all()
        print(f"✓ Database inizializzato: {db_path}")


def get_database_info(app: Flask) -> dict:
    """
    Ottiene informazioni sul database

    Args:
        app: Istanza dell'applicazione Flask

    Returns:
        Dizionario con informazioni sul database
    """
    with app.app_context():
        try:
            # Ottieni statistiche sulle tabelle
            from models import (
                MenuItem, MenuType, Message, MessageType, MessagePriority,
                Notification, NotificationType, NotificationCategory, NotificationPriority
            )

            stats = {
                'database_path': app.config.get('SQLALCHEMY_DATABASE_URI'),
                'tables': {
                    'menu_items': MenuItem.query.count(),
                    'menu_types': MenuType.query.count(),
                    'messages': Message.query.count(),
                    'message_types': MessageType.query.count(),
                    'message_priorities': MessagePriority.query.count(),
                    'notifications': Notification.query.count(),
                    'notification_types': NotificationType.query.count(),
                    'notification_categories': NotificationCategory.query.count(),
                    'notification_priorities': NotificationPriority.query.count(),
                },
                'unread_messages': Message.query.filter_by(unread=True).count(),
                'unread_notifications': Notification.query.filter_by(read=False).count(),
                'active_menu_items': MenuItem.query.filter_by(enabled=True).count(),
            }

            # Calcola la dimensione del file database se esiste
            db_path = Path(app.instance_path) / 'adminlte.db'
            if db_path.exists():
                stats['database_size'] = db_path.stat().st_size
                stats['database_size_mb'] = round(stats['database_size'] / (1024 * 1024), 2)

            return stats

        except Exception as e:
            return {'error': str(e)}


def reset_database(app: Flask) -> bool:
    """
    Resetta completamente il database (elimina e ricrea tutte le tabelle)

    Args:
        app: Istanza dell'applicazione Flask

    Returns:
        True se il reset è riuscito, False altrimenti
    """
    try:
        with app.app_context():
            # Elimina tutte le tabelle
            db.drop_all()
            print("✓ Tabelle eliminate")

            # Ricrea tutte le tabelle
            db.create_all()
            print("✓ Tabelle ricreate")

            return True

    except Exception as e:
        print(f"✗ Errore nel reset del database: {e}")
        return False


def backup_database(app: Flask, backup_path: str = None) -> str:
    """
    Crea un backup del database

    Args:
        app: Istanza dell'applicazione Flask
        backup_path: Percorso per il backup (opzionale)

    Returns:
        Percorso del file di backup creato
    """
    import shutil
    from datetime import datetime

    try:
        db_path = Path(app.instance_path) / 'adminlte.db'

        if not db_path.exists():
            raise FileNotFoundError("Database file not found")

        if backup_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = Path(app.instance_path) / f'adminlte_backup_{timestamp}.db'
        else:
            backup_path = Path(backup_path)

        # Crea la directory di backup se non esiste
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        # Copia il database
        shutil.copy2(db_path, backup_path)

        print(f"✓ Backup creato: {backup_path}")
        return str(backup_path)

    except Exception as e:
        print(f"✗ Errore nel backup: {e}")
        raise


def restore_database(app: Flask, backup_path: str) -> bool:
    """
    Ripristina il database da un backup

    Args:
        app: Istanza dell'applicazione Flask
        backup_path: Percorso del file di backup

    Returns:
        True se il ripristino è riuscito, False altrimenti
    """
    import shutil

    try:
        backup_path = Path(backup_path)

        if not backup_path.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")

        db_path = Path(app.instance_path) / 'adminlte.db'

        # Crea un backup del database corrente
        if db_path.exists():
            current_backup = backup_database(app, db_path.with_suffix('.db.pre_restore'))
            print(f"✓ Backup corrente salvato in: {current_backup}")

        # Ripristina il database
        shutil.copy2(backup_path, db_path)

        print(f"✓ Database ripristinato da: {backup_path}")
        return True

    except Exception as e:
        print(f"✗ Errore nel ripristino: {e}")
        return False


def optimize_database(app: Flask) -> bool:
    """
    Ottimizza il database SQLite (VACUUM e ANALYZE)

    Args:
        app: Istanza dell'applicazione Flask

    Returns:
        True se l'ottimizzazione è riuscita, False altrimenti
    """
    try:
        with app.app_context():
            # Esegui VACUUM per ottimizzare lo spazio
            db.engine.execute('VACUUM')
            print("✓ VACUUM completato")

            # Esegui ANALYZE per aggiornare le statistiche
            db.engine.execute('ANALYZE')
            print("✓ ANALYZE completato")

            return True

    except Exception as e:
        print(f"✗ Errore nell'ottimizzazione: {e}")
        return False


def check_database_integrity(app: Flask) -> dict:
    """
    Controlla l'integrità del database

    Args:
        app: Istanza dell'applicazione Flask

    Returns:
        Risultato del controllo di integrità
    """
    try:
        with app.app_context():
            # Esegui il controllo di integrità
            result = db.engine.execute('PRAGMA integrity_check').fetchall()

            integrity_result = {
                'status': 'ok' if len(result) == 1 and result[0][0] == 'ok' else 'error',
                'details': [row[0] for row in result],
                'timestamp': datetime.now().isoformat()
            }

            return integrity_result

    except Exception as e:
        return {
            'status': 'error',
            'details': [str(e)],
            'timestamp': datetime.now().isoformat()
        }


def cleanup_old_data(app: Flask, days: int = 30) -> dict:
    """
    Pulisce i dati vecchi dal database

    Args:
        app: Istanza dell'applicazione Flask
        days: Numero di giorni oltre i quali i dati vengono considerati vecchi

    Returns:
        Statistiche sulla pulizia effettuata
    """
    from datetime import datetime, timedelta
    from models import Message, Notification

    try:
        with app.app_context():
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            # Conta i record da eliminare
            old_messages = Message.query.filter(
                Message.created_at < cutoff_date,
                Message.archived == True
            ).count()

            old_notifications = Notification.query.filter(
                Notification.created_at < cutoff_date,
                Notification.dismissed == True
            ).count()

            # Elimina i record vecchi
            Message.query.filter(
                Message.created_at < cutoff_date,
                Message.archived == True
            ).delete()

            Notification.query.filter(
                Notification.created_at < cutoff_date,
                Notification.dismissed == True
            ).delete()

            db.session.commit()

            cleanup_stats = {
                'status': 'success',
                'deleted_messages': old_messages,
                'deleted_notifications': old_notifications,
                'cutoff_date': cutoff_date.isoformat(),
                'days': days
            }

            print(f"✓ Pulizia completata: {old_messages} messaggi e {old_notifications} notifiche eliminati")
            return cleanup_stats

    except Exception as e:
        print(f"✗ Errore nella pulizia: {e}")
        return {
            'status': 'error',
            'error': str(e)
        }