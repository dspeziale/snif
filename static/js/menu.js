/**
 * Menu Manager per AdminLTE 4
 * Gestisce il caricamento dinamico del menu dalla API
 */

class MenuRenderer {
    constructor() {
        this.menuContainer = null;
        this.menuData = [];
        this.init();
    }

    async init() {
        this.menuContainer = document.getElementById('navigation');
        if (!this.menuContainer) {
            console.error('Container del menu non trovato');
            return;
        }

        await this.loadMenuData();
        this.renderMenu();
    }

    async loadMenuData() {
        try {
            const response = await fetch('/menu/api/menus');
            const result = await response.json();

            if (result.success) {
                this.menuData = result.data;
            } else {
                console.error('Errore nel caricamento del menu:', result.message);
                this.showFallbackMenu();
            }
        } catch (error) {
            console.error('Errore di connessione:', error);
            this.showFallbackMenu();
        }
    }

    renderMenu() {
        if (!this.menuContainer) return;

        let html = '';

        this.menuData.forEach(menuItem => {
            html += this.renderMenuItem(menuItem);
        });

        this.menuContainer.innerHTML = html;

        // Riattiva AdminLTE treeview dopo il rendering
        this.initializeTreeview();
    }

    renderMenuItem(item, level = 0) {
        if (!item.is_active) return '';

        // Se è un header
        if (item.is_header) {
            return `<li class="nav-header">${item.title}</li>`;
        }

        let html = '';
        const hasChildren = item.children && item.children.length > 0;
        const activeClass = this.isCurrentPage(item.url) ? 'active' : '';
        const menuOpenClass = this.hasActiveChild(item) ? 'menu-open' : '';

        if (hasChildren) {
            // Menu con sottomenu
            html += `
                <li class="nav-item ${menuOpenClass}">
                    <a href="#" class="nav-link ${activeClass}">
                        <i class="nav-icon ${item.icon}"></i>
                        <p>
                            ${item.title}
                            <i class="nav-arrow bi bi-chevron-right"></i>
                        </p>
                    </a>
                    <ul class="nav nav-treeview">
            `;

            // Renderizza i figli
            item.children.forEach(child => {
                html += this.renderMenuItem(child, level + 1);
            });

            html += `
                    </ul>
                </li>
            `;
        } else {
            // Menu semplice
            const url = item.url || '#';
            html += `
                <li class="nav-item">
                    <a href="${url}" class="nav-link ${activeClass}">
                        <i class="nav-icon ${item.icon}"></i>
                        <p>${item.title}</p>
                    </a>
                </li>
            `;
        }

        return html;
    }

    isCurrentPage(url) {
        if (!url) return false;

        const currentPath = window.location.pathname;

        // Exact match
        if (currentPath === url) return true;

        // Se è la home page
        if (url === '/' && (currentPath === '/' || currentPath === '/index')) {
            return true;
        }

        return false;
    }

    hasActiveChild(item) {
        if (!item.children) return false;

        return item.children.some(child => {
            return this.isCurrentPage(child.url) || this.hasActiveChild(child);
        });
    }

    initializeTreeview() {
        // Reinitializza AdminLTE treeview
        if (typeof window.AdminLTE !== 'undefined') {
            // Rimuovi event listeners esistenti
            const treeviewItems = document.querySelectorAll('[data-lte-toggle="treeview"]');
            treeviewItems.forEach(item => {
                // AdminLTE gestisce automaticamente i treeview
            });
        }

        // Assicurati che i menu aperti rimangano aperti
        const activeItems = document.querySelectorAll('.nav-link.active');
        activeItems.forEach(activeItem => {
            let parent = activeItem.closest('.nav-item');
            while (parent) {
                if (parent.classList.contains('nav-item') && parent.querySelector('.nav-treeview')) {
                    parent.classList.add('menu-open');
                }
                parent = parent.parentElement.closest('.nav-item');
            }
        });
    }

    showFallbackMenu() {
        if (!this.menuContainer) return;

        this.menuContainer.innerHTML = `
            <li class="nav-item">
                <a href="/" class="nav-link active">
                    <i class="nav-icon bi bi-speedometer"></i>
                    <p>Dashboard</p>
                </a>
            </li>
            <li class="nav-item">
                <a href="/menu" class="nav-link">
                    <i class="nav-icon bi bi-list-ul"></i>
                    <p>Menu Management</p>
                </a>
            </li>
            <li class="nav-header">MENU NON DISPONIBILE</li>
            <li class="nav-item">
                <div class="nav-link text-danger">
                    <i class="nav-icon bi bi-exclamation-triangle"></i>
                    <p>Errore caricamento menu</p>
                </div>
            </li>
        `;
    }

    // Metodo pubblico per ricaricare il menu
    async reload() {
        await this.loadMenuData();
        this.renderMenu();
    }
}

// Inizializza il renderer del menu quando il DOM è pronto
document.addEventListener('DOMContentLoaded', function() {
    // Attendi che AdminLTE sia caricato
    setTimeout(() => {
        window.menuRenderer = new MenuRenderer();
    }, 100);
});

// Esponi globalmente per uso in altre parti dell'applicazione
window.MenuRenderer = MenuRenderer;