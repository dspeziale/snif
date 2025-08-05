#!/usr/bin/env python3
"""
Script per inizializzare il database SQLite con la struttura dei menu
"""

import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Aggiungi il percorso del progetto
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models import db, Menu


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///adminlte.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    return app


def init_database():
    """Inizializza il database e crea il menu di default"""
    app = create_app()

    with app.app_context():
        print("Creazione delle tabelle...")
        db.create_all()

        # Verifica se esistono già menu
        menu_count = Menu.query.count()
        print(f"Menu esistenti nel database: {menu_count}")

        if menu_count == 0:
            print("Creazione del menu di default...")
            Menu.create_default_menu()
            print("Menu di default creato con successo!")

            # Verifica la creazione
            new_count = Menu.query.count()
            print(f"Numero di menu creati: {new_count}")

            # Mostra la struttura creata
            print("\nStruttura menu creata:")
            root_menus = Menu.query.filter_by(parent_id=None).order_by(Menu.order_position).all()
            for menu in root_menus:
                print_menu_tree(menu, 0)
        else:
            print("Menu già esistenti, non è necessario crearli.")

            # Mostra la struttura esistente
            print("\nStruttura menu esistente:")
            root_menus = Menu.query.filter_by(parent_id=None).order_by(Menu.order_position).all()
            for menu in root_menus:
                print_menu_tree(menu, 0)


def print_menu_tree(menu, level):
    """Stampa la struttura ad albero dei menu"""
    indent = "  " * level
    icon = f"[{menu.icon}]" if menu.icon else ""
    url = f" -> {menu.url}" if menu.url else ""
    status = " (HEADER)" if menu.is_header else ""
    active = " (INATTIVO)" if not menu.is_active else ""

    print(f"{indent}{icon} {menu.title}{url}{status}{active}")

    for child in menu.children:
        print_menu_tree(child, level + 1)


def reset_database():
    """Resetta completamente il database"""
    app = create_app()

    with app.app_context():
        print("ATTENZIONE: Questo cancellerà tutti i dati esistenti!")
        confirm = input("Sei sicuro di voler continuare? (yes/no): ")

        if confirm.lower() == 'yes':
            print("Eliminazione delle tabelle...")
            db.drop_all()
            print("Ricreazione delle tabelle...")
            db.create_all()
            print("Creazione del menu di default...")
            Menu.create_default_menu()
            print("Database resettato e menu ricreato con successo!")
        else:
            print("Operazione annullata.")


def show_menu_stats():
    """Mostra statistiche sui menu"""
    app = create_app()

    with app.app_context():
        total = Menu.query.count()
        active = Menu.query.filter_by(is_active=True).count()
        headers = Menu.query.filter_by(is_header=True).count()
        root_level = Menu.query.filter_by(parent_id=None).count()
        level_1 = Menu.query.join(Menu, Menu.id == Menu.parent_id).filter(Menu.parent_id == None).count()
        level_2 = Menu.query.join(Menu, Menu.id == Menu.parent_id).join(Menu, Menu.id == Menu.parent_id).filter(
            Menu.parent_id == None).count()

        print(f"\n=== STATISTICHE MENU ===")
        print(f"Totale menu: {total}")
        print(f"Menu attivi: {active}")
        print(f"Menu inattivi: {total - active}")
        print(f"Headers: {headers}")
        print(f"Menu root (livello 0): {root_level}")
        print(f"Menu livello 1: {level_1}")
        print(f"Menu livello 2: {level_2}")


def add_sample_menu():
    """Aggiunge un menu di esempio"""
    app = create_app()

    with app.app_context():
        print("Aggiunta di un menu di esempio...")

        # Trova la posizione massima
        max_order = db.session.query(db.func.max(Menu.order_position)).filter_by(parent_id=None).scalar() or 0

        # Crea un nuovo menu
        sample_menu = Menu(
            title='Menu di Test',
            icon='bi-star',
            url='/test',
            order_position=max_order + 1,
            is_active=True
        )

        db.session.add(sample_menu)
        db.session.commit()

        print(f"Menu di test creato con ID: {sample_menu.id}")


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Uso: python init_db.py [comando]")
        print("\nComandi disponibili:")
        print("  init     - Inizializza il database e crea il menu di default")
        print("  reset    - Resetta completamente il database")
        print("  stats    - Mostra statistiche sui menu")
        print("  sample   - Aggiunge un menu di esempio")
        print("  show     - Mostra la struttura dei menu esistenti")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == 'init':
        init_database()
    elif command == 'reset':
        reset_database()
    elif command == 'stats':
        show_menu_stats()
    elif command == 'sample':
        add_sample_menu()
    elif command == 'show':
        app = create_app()
        with app.app_context():
            print("Struttura menu esistente:")
            root_menus = Menu.query.filter_by(parent_id=None).order_by(Menu.order_position).all()
            if root_menus:
                for menu in root_menus:
                    print_menu_tree(menu, 0)
            else:
                print("Nessun menu trovato nel database.")
    else:
        print(f"Comando non riconosciuto: {command}")
        sys.exit(1)