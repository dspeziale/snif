"""
Script per verificare e visualizzare il contenuto del database menu
"""

from menu_database import MenuDatabase
import json


def verify_menu_database(db_path='menu.db'):
    """Verifica e visualizza il contenuto del database menu"""

    print("=" * 60)
    print("VERIFICA DATABASE MENU")
    print("=" * 60)

    db = MenuDatabase(db_path)

    # 1. Conta totale menu items
    all_items = db.get_flat_menu_list()
    print(f"\n📊 Totale menu items nel database: {len(all_items)}")

    # 2. Mostra struttura ad albero
    print("\n🌳 STRUTTURA MENU AD ALBERO:")
    print("-" * 40)

    def print_tree(items, indent=0):
        for item in items:
            prefix = "  " * indent
            icon = f"[{item.icon}]" if item.icon else ""
            url = f"-> {item.url}" if item.url else ""
            item_type = f"({item.type})" if item.type == 'header' else ""

            print(f"{prefix}{'├── ' if indent > 0 else ''}{item.text} {icon} {item_type} {url}")

            if item.children:
                print_tree(item.children, indent + 1)

    menu_tree = db.get_menu_tree()
    print_tree(menu_tree)

    # 3. Mostra lista piatta con dettagli
    print("\n📋 LISTA DETTAGLIATA MENU ITEMS:")
    print("-" * 40)

    for item in all_items:
        print(f"\nID: {item.id}")
        print(f"  Tipo: {item.type}")
        print(f"  Testo: {item.text}")
        print(f"  Parent ID: {item.parent_id}")
        print(f"  Icona: {item.icon}")
        print(f"  URL: {item.url}")
        print(f"  Attivo: {item.active}")
        print(f"  Posizione: {item.position}")
        if item.badge_text:
            print(f"  Badge: {item.badge_text} ({item.badge_color})")

    # 4. Esporta in JSON per verifica
    print("\n💾 ESPORTAZIONE JSON:")
    print("-" * 40)
    json_export = db.export_to_json()
    print(json.dumps(json_export, indent=2, ensure_ascii=False))

    # 5. Test di ricerca
    print("\n🔍 TEST RICERCA:")
    print("-" * 40)
    search_terms = ['Dashboard', 'menu', 'admin']
    for term in search_terms:
        results = db.search_menu_items(term)
        print(f"Ricerca '{term}': {len(results)} risultati")
        for r in results:
            print(f"  - {r.text} ({r.url})")

    # 6. Statistiche
    print("\n📈 STATISTICHE:")
    print("-" * 40)
    headers = [item for item in all_items if item.type == 'header']
    items = [item for item in all_items if item.type == 'item']
    with_children = [item for item in all_items if item.parent_id is not None]
    active_items = [item for item in all_items if item.active]

    print(f"Headers: {len(headers)}")
    print(f"Menu Items: {len(items)}")
    print(f"Root items: {len(all_items) - len(with_children)}")
    print(f"Child items: {len(with_children)}")
    print(f"Active items: {len(active_items)}")

    return db


def test_crud_operations():
    """Test delle operazioni CRUD"""
    print("\n" + "=" * 60)
    print("TEST OPERAZIONI CRUD")
    print("=" * 60)

    db = MenuDatabase('menu.db')

    # Test inserimento
    from menu_database import MenuItem

    test_item = MenuItem(
        type='item',
        text='Test Item',
        icon='bi-test',
        url='/test',
        position=999
    )

    print("\n✅ Test Inserimento:")
    item_id = db.insert_menu_item(test_item)
    print(f"  Inserito item con ID: {item_id}")

    # Test lettura
    print("\n✅ Test Lettura:")
    retrieved = db.get_menu_item(item_id)
    if retrieved:
        print(f"  Recuperato: {retrieved.text} (ID: {retrieved.id})")

    # Test aggiornamento
    print("\n✅ Test Aggiornamento:")
    retrieved.text = "Test Item Modificato"
    retrieved.icon = "bi-check-circle"
    success = db.update_menu_item(retrieved)
    print(f"  Aggiornamento: {'Riuscito' if success else 'Fallito'}")

    # Verifica aggiornamento
    updated = db.get_menu_item(item_id)
    if updated:
        print(f"  Nuovo testo: {updated.text}")
        print(f"  Nuova icona: {updated.icon}")

    # Test eliminazione
    print("\n✅ Test Eliminazione:")
    success = db.delete_menu_item(item_id)
    print(f"  Eliminazione: {'Riuscita' if success else 'Fallita'}")

    # Verifica eliminazione
    deleted = db.get_menu_item(item_id)
    print(f"  Verifica: {'Item non trovato (corretto)' if not deleted else 'Item ancora presente (errore)'}")


if __name__ == "__main__":
    # Esegui verifica principale
    db = verify_menu_database()

    # Esegui test CRUD
    test_crud_operations()

    print("\n" + "=" * 60)
    print("✅ VERIFICA COMPLETATA")
    print("=" * 60)