/**
 * Menu Manager - Gestisce il caricamento dinamico del menu della sidebar
 */
class MenuManager {
    constructor() {
        this.menuContainer = document.getElementById('navigation');
        this.currentPath = window.location.pathname;
        this.init();
    }

    init() {
        this.loadMenu();
    }

    /**
     * Carica il menu tramite AJAX
     */
    async loadMenu() {
        try {
            const response = await fetch(`/api/menu?current_path=${encodeURIComponent(this.currentPath)}`);
            const result = await response.json();

            if (result.success) {
                this.renderMenu(result.data);
                this.initializeTreeview();
            } else {
                console.error('Errore nel caricamento del menu:', result.error);
                this.showErrorMessage();
            }
        } catch (error) {
            console.error('Errore nella chiamata AJAX:', error);
            this.showErrorMessage();
        }
    }

    /**
     * Renderizza il menu HTML
     */
    renderMenu(menuItems) {
        if (!this.menuContainer) {
            console.error('Container del menu non trovato');
            return;
        }

        const menuHTML = this.buildMenuHTML(menuItems);
        this.menuContainer.innerHTML = menuHTML;
    }

    /**
     * Costruisce l'HTML del menu ricorsivamente
     */
    buildMenuHTML(items, level = 0) {
        let html = '';

        items.forEach(item => {
            if (item.type === 'header') {
                html += this.buildHeaderHTML(item);
            } else {
                html += this.buildMenuItemHTML(item, level);
            }
        });

        return html;
    }

    /**
     * Costruisce l'HTML per un header del menu
     */
    buildHeaderHTML(item) {
        return `<li class="nav-header">${item.title}</li>`;
    }

    /**
     * Costruisce l'HTML per un elemento del menu
     */
    buildMenuItemHTML(item, level) {
        const hasChildren = item.children && item.children.length > 0;
        const isActive = item.active ? 'active' : '';
        const isOpen = item.open ? 'menu-open' : '';
        const url = item.url || '#';

        let html = `<li class="nav-item ${isOpen}">`;

        // Link principale
        html += `<a href="${url}" class="nav-link ${isActive}" data-menu-id="${item.id}">`;
        html += `<i class="nav-icon ${item.icon}"></i>`;
        html += `<p>${item.title}`;

        // Badge se presente
        if (item.badge) {
            html += `<span class="${item.badge.class}">${item.badge.text}</span>`;
        }

        // Freccia per sottomenu
        if (hasChildren) {
            html += `<i class="nav-arrow bi bi-chevron-right"></i>`;
        }

        html += `</p></a>`;

        // Sottomenu
        if (hasChildren) {
            html += `<ul class="nav nav-treeview">`;
            html += this.buildMenuHTML(item.children, level + 1);
            html += `</ul>`;
        }

        html += `</li>`;

        return html;
    }

    /**
     * Inizializza la funzionalità treeview di AdminLTE
     */
    initializeTreeview() {
        // Reinizializza il treeview di AdminLTE
        if (typeof window.lte !== 'undefined' && window.lte.Treeview) {
            const treeviewElements = document.querySelectorAll('[data-lte-toggle="treeview"]');
            treeviewElements.forEach(element => {
                new window.lte.Treeview(element);
            });
        }

        // Aggiungi event listeners per i link del menu
        this.attachMenuEventListeners();
    }

    /**
     * Aggiunge event listeners ai link del menu
     */
    attachMenuEventListeners() {
        const menuLinks = this.menuContainer.querySelectorAll('.nav-link[data-menu-id]');

        menuLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                const url = link.getAttribute('href');
                const menuId = link.getAttribute('data-menu-id');

                // Se il link non è "#", naviga normalmente
                if (url !== '#') {
                    // Aggiorna lo stato attivo del menu
                    this.updateActiveMenu(url);
                }
            });
        });
    }

    /**
     * Aggiorna l'elemento del menu attivo
     */
    async updateActiveMenu(newPath) {
        try {
            const response = await fetch('/api/menu/update-active', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    current_path: newPath
                })
            });

            const result = await response.json();

            if (result.success) {
                // Rimuovi le classi attive correnti
                this.clearActiveStates();

                // Applica i nuovi stati attivi
                this.applyActiveStates(result.data);
            }
        } catch (error) {
            console.error('Errore nell\'aggiornamento del menu attivo:', error);
        }
    }

    /**
     * Rimuove tutti gli stati attivi dal menu
     */
    clearActiveStates() {
        const activeLinks = this.menuContainer.querySelectorAll('.nav-link.active');
        const openItems = this.menuContainer.querySelectorAll('.nav-item.menu-open');

        activeLinks.forEach(link => link.classList.remove('active'));
        openItems.forEach(item => item.classList.remove('menu-open'));
    }

    /**
     * Applica gli stati attivi basati sui dati del menu
     */
    applyActiveStates(menuItems) {
        this.applyActiveStatesRecursive(menuItems);
    }

    /**
     * Applica ricorsivamente gli stati attivi
     */
    applyActiveStatesRecursive(items) {
        items.forEach(item => {
            if (item.type === 'header') return;

            const menuElement = this.menuContainer.querySelector(`[data-menu-id="${item.id}"]`);
            const parentItem = menuElement?.closest('.nav-item');

            if (menuElement && parentItem) {
                // Applica stato attivo
                if (item.active) {
                    menuElement.classList.add('active');
                }

                // Applica stato aperto
                if (item.open) {
                    parentItem.classList.add('menu-open');
                }
            }

            // Applica ricorsivamente ai children
            if (item.children && item.children.length > 0) {
                this.applyActiveStatesRecursive(item.children);
            }
        });
    }

    /**
     * Mostra un messaggio di errore
     */
    showErrorMessage() {
        if (this.menuContainer) {
            this.menuContainer.innerHTML = `
                <li class="nav-item">
                    <div class="nav-link text-danger">
                        <i class="nav-icon bi bi-exclamation-triangle"></i>
                        <p>Errore nel caricamento del menu</p>
                    </div>
                </li>
            `;
        }
    }

    /**
     * Ricarica il menu
     */
    reload() {
        this.currentPath = window.location.pathname;
        this.loadMenu();
    }
}

// Inizializza il MenuManager quando il DOM è pronto
document.addEventListener('DOMContentLoaded', function() {
    window.menuManager = new MenuManager();
});

// Aggiorna il menu quando la pagina cambia (per SPA)
window.addEventListener('popstate', function() {
    if (window.menuManager) {
        window.menuManager.reload();
    }
});