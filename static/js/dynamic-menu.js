/**
 * Dynamic Menu Loader - Versione Semplice
 */

class SimpleMenuLoader {
    constructor() {
        this.menuContainer = null;
        this.isLoaded = false; // Previeni caricamenti multipli
        this.init();
    }

    init() {
        // Aspetta che il DOM sia pronto
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setup());
        } else {
            this.setup();
        }
    }

    setup() {
        if (this.isLoaded) {
            console.log('Menu già caricato, salto...');
            return;
        }

        this.menuContainer = document.getElementById('sidebar-menu');

        if (!this.menuContainer) {
            console.error('Menu container #sidebar-menu non trovato!');
            return;
        }

        console.log('Menu container trovato, carico il menu...');
        this.loadMenu();
    }

    async loadMenu() {
        if (this.isLoaded) {
            console.log('Menu già caricato');
            return;
        }

        try {
            console.log('Inizio caricamento menu...');

            const response = await fetch('/api/menu');
            if (!response.ok) {
                throw new Error(`Errore HTTP: ${response.status}`);
            }

            const data = await response.json();
            console.log('Dati menu ricevuti:', data);

            if (data.success && data.menu_items) {
                this.renderMenu(data.menu_items);
                this.isLoaded = true; // Marca come caricato
                console.log('Menu renderizzato con successo');
            } else {
                throw new Error('Formato dati menu non valido');
            }

        } catch (error) {
            console.error('Errore caricamento menu:', error);
            this.showError();
        }
    }

    renderMenu(menuItems) {
        // Pulisci il contenitore
        this.menuContainer.innerHTML = '';

        // Renderizza ogni elemento
        menuItems.forEach(item => {
            const element = this.createMenuElement(item);
            this.menuContainer.appendChild(element);
        });

        // Aggiungi CSS inline di emergenza per i sottomenu
        this.addEmergencyCSS();

        // Re-inizializza AdminLTE treeview
        this.initTreeview();
    }

    addEmergencyCSS() {
        // CSS inline per assicurarsi che i sottomenu funzionino
        const style = document.createElement('style');
        style.textContent = `
            .nav-item.menu-closed .nav-treeview {
                display: none !important;
            }
            .nav-item.menu-open .nav-treeview {
                display: block !important;
            }
            .nav-arrow {
                transition: transform 0.3s ease !important;
            }
            .nav-item.menu-open .nav-arrow {
                transform: rotate(90deg) !important;
            }
        `;

        if (!document.querySelector('#emergency-menu-css')) {
            style.id = 'emergency-menu-css';
            document.head.appendChild(style);
            console.log('CSS di emergenza aggiunto');
        }
    }

    createMenuElement(item) {
        if (item.type === 'header') {
            return this.createHeader(item);
        } else {
            return this.createMenuItem(item);
        }
    }

    createHeader(item) {
        const li = document.createElement('li');
        li.className = 'nav-header';
        li.textContent = item.title;
        return li;
    }

    createMenuItem(item) {
        const li = document.createElement('li');
        li.className = 'nav-item';

        // Aggiungi classe per menu con children
        if (item.has_children) {
            li.classList.add(item.active ? 'menu-open' : 'menu-closed');
        }

        // Link principale
        const link = document.createElement('a');
        link.href = item.url || '#';
        link.className = `nav-link ${item.active ? 'active' : ''}`;

        // Icona
        if (item.icon) {
            const icon = document.createElement('i');
            icon.className = `nav-icon ${item.icon}`;
            link.appendChild(icon);
        }

        // Testo
        const text = document.createElement('p');
        text.textContent = item.title;

        // Badge
        if (item.badge) {
            const badge = document.createElement('span');
            badge.className = item.badge.class;
            badge.textContent = item.badge.text;
            text.appendChild(badge);
        }

        // Freccia per sottomenu
        if (item.has_children) {
            const arrow = document.createElement('i');
            arrow.className = 'nav-arrow bi bi-chevron-right';
            text.appendChild(arrow);
        }

        link.appendChild(text);
        li.appendChild(link);

        // Sottomenu
        if (item.has_children && item.children) {
            const submenu = this.createSubmenu(item.children);
            li.appendChild(submenu);

            // Aggiungi evento click per toggle
            link.addEventListener('click', (e) => {
                if (item.url === '#') {
                    e.preventDefault();
                    this.toggleSubmenu(li);
                }
            });
        }

        return li;
    }

    createSubmenu(children) {
        const ul = document.createElement('ul');
        ul.className = 'nav nav-treeview';

        children.forEach(child => {
            const li = document.createElement('li');
            li.className = 'nav-item';

            const link = document.createElement('a');
            link.href = child.url;
            link.className = `nav-link ${child.active ? 'active' : ''}`;

            // Icona child
            if (child.icon) {
                const icon = document.createElement('i');
                icon.className = `nav-icon ${child.icon}`;
                link.appendChild(icon);
            }

            // Testo child
            const text = document.createElement('p');
            text.textContent = child.title;
            link.appendChild(text);

            li.appendChild(link);
            ul.appendChild(li);
        });

        return ul;
    }

    showError() {
        this.menuContainer.innerHTML = `
            <li class="nav-item">
                <div class="alert alert-danger m-2">
                    <i class="bi bi-exclamation-triangle"></i>
                    <small>Errore caricamento menu</small>
                </div>
            </li>
            <li class="nav-item">
                <a href="/" class="nav-link">
                    <i class="nav-icon bi bi-house"></i>
                    <p>Home</p>
                </a>
            </li>
        `;
    }

    initTreeview() {
        // Non serve più setupTreeviewBehavior perché gestiamo i click direttamente in createMenuItem
        console.log('Treeview inizializzato');
    }

    toggleSubmenu(menuItem) {
        console.log('Toggle submenu per:', menuItem.querySelector('.nav-link')?.textContent?.trim());

        const treeview = menuItem.querySelector('.nav-treeview');
        if (!treeview) {
            console.log('Nessun sottomenu trovato');
            return;
        }

        // Debug stato attuale
        console.log('Stato attuale:', {
            hasMenuOpen: menuItem.classList.contains('menu-open'),
            hasMenuClosed: menuItem.classList.contains('menu-closed'),
            treeviewDisplay: window.getComputedStyle(treeview).display,
            treeviewHeight: window.getComputedStyle(treeview).maxHeight
        });

        if (menuItem.classList.contains('menu-open')) {
            console.log('Chiudo menu');
            menuItem.classList.remove('menu-open');
            menuItem.classList.add('menu-closed');
        } else {
            console.log('Apro menu');
            menuItem.classList.remove('menu-closed');
            menuItem.classList.add('menu-open');
        }

        // Anima la freccia
        const arrow = menuItem.querySelector('.nav-arrow');
        if (arrow) {
            if (menuItem.classList.contains('menu-open')) {
                arrow.style.transform = 'rotate(90deg)';
                console.log('Freccia ruotata a 90°');
            } else {
                arrow.style.transform = 'rotate(0deg)';
                console.log('Freccia ruotata a 0°');
            }
        }

        // Debug stato finale
        setTimeout(() => {
            console.log('Stato finale:', {
                hasMenuOpen: menuItem.classList.contains('menu-open'),
                hasMenuClosed: menuItem.classList.contains('menu-closed'),
                treeviewDisplay: window.getComputedStyle(treeview).display,
                treeviewHeight: window.getComputedStyle(treeview).maxHeight,
                treeviewOpacity: window.getComputedStyle(treeview).opacity
            });
        }, 100);
    }

    setupTreeviewBehavior() {
        // Questo metodo non è più necessario
        console.log('Setup treeview behavior completato');
    }

    // Metodo pubblico per ricaricare il menu
    refresh() {
        console.log('Ricarico il menu manualmente...');
        this.isLoaded = false; // Reset flag per permettere ricaricamento
        this.loadMenu();
    }

    // Metodo di debug
    debug() {
        console.log('=== DEBUG MENU ===');
        console.log('Container:', this.menuContainer);
        console.log('Menu caricato:', this.isLoaded);

        const menuItems = this.menuContainer.querySelectorAll('.nav-item');
        console.log('Elementi menu trovati:', menuItems.length);

        const submenuItems = this.menuContainer.querySelectorAll('.nav-item .nav-treeview');
        console.log('Sottomenu trovati:', submenuItems.length);

        menuItems.forEach((item, index) => {
            const link = item.querySelector('.nav-link');
            const hasSubmenu = item.querySelector('.nav-treeview');
            console.log(`Menu ${index + 1}:`, {
                text: link?.textContent?.trim(),
                href: link?.href,
                hasSubmenu: !!hasSubmenu,
                classes: item.className
            });
        });

        return {
            container: this.menuContainer,
            isLoaded: this.isLoaded,
            menuCount: menuItems.length,
            submenuCount: submenuItems.length
        };
    }
}

// Inizializza il loader del menu SOLO UNA VOLTA
if (!window.menuLoader) {
    const menuLoader = new SimpleMenuLoader();

    // Esponi globalmente per debug
    window.menuLoader = menuLoader;

    console.log('Dynamic Menu System caricato');
} else {
    console.log('Menu loader già esistente, non ricreo');
}