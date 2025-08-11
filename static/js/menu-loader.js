/**
 * Menu Loader - Carica dinamicamente i menu tramite AJAX
 * Aggiungi questo file nella cartella static/js/
 */

class MenuLoader {
    constructor() {
        this.apiBaseUrl = '/api/menu';
        this.currentPath = window.location.pathname;
        this.sidebarElement = null;
        this.navbarElement = null;
    }

    /**
     * Inizializza il caricamento dei menu
     */
    async init() {
        try {
            // Carica sia sidebar che navbar
            await Promise.all([
                this.loadSidebar(),
                this.loadNavbar()
            ]);

            // Reinizializza i componenti AdminLTE dopo il caricamento
            this.initializeAdminLTEComponents();
        } catch (error) {
            console.error('Errore nel caricamento dei menu:', error);
        }
    }

    /**
     * Carica il menu sidebar tramite AJAX
     */
    async loadSidebar() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/sidebar?current_path=${encodeURIComponent(this.currentPath)}`);
            const data = await response.json();

            this.renderSidebar(data);
        } catch (error) {
            console.error('Errore nel caricamento del sidebar:', error);
        }
    }

    /**
     * Carica il menu navbar tramite AJAX
     */
    async loadNavbar() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/navbar`);
            const data = await response.json();

            this.renderNavbar(data);
        } catch (error) {
            console.error('Errore nel caricamento della navbar:', error);
        }
    }

    /**
     * Renderizza il sidebar con i dati ricevuti
     */
    renderSidebar(data) {
        const sidebarWrapper = document.querySelector('.sidebar-wrapper');
        if (!sidebarWrapper) return;

        // Genera HTML per il brand
        const brandHtml = this.generateBrandHtml(data.brand);

        // Genera HTML per il menu
        const menuHtml = this.generateSidebarMenuHtml(data.items);

        // Inserisci il brand prima del wrapper
        const sidebar = document.querySelector('.app-sidebar');
        const existingBrand = sidebar.querySelector('.sidebar-brand');
        if (existingBrand) {
            existingBrand.innerHTML = brandHtml;
        } else {
            const brandDiv = document.createElement('div');
            brandDiv.className = 'sidebar-brand';
            brandDiv.innerHTML = brandHtml;
            sidebar.insertBefore(brandDiv, sidebarWrapper);
        }

        // Inserisci il menu nel wrapper
        sidebarWrapper.innerHTML = `
            <nav class="mt-2">
                <ul class="nav sidebar-menu flex-column"
                    data-lte-toggle="treeview"
                    role="navigation"
                    aria-label="Main navigation"
                    data-accordion="false"
                    id="navigation">
                    ${menuHtml}
                </ul>
            </nav>
        `;
    }

    /**
     * Genera HTML per il brand del sidebar
     */
    generateBrandHtml(brand) {
        if (!brand) return '';

        return `
            <a href="${brand.link || '/'}" class="brand-link">
                ${brand.logo ? `<img src="${brand.logo}" alt="${brand.text} Logo" class="brand-image opacity-75 shadow" />` : ''}
                ${brand.text ? `<span class="brand-text fw-light">${brand.text}</span>` : ''}
            </a>
        `;
    }

    /**
     * Genera HTML per le voci del menu sidebar
     */
    generateSidebarMenuHtml(items) {
        let html = '';

        items.forEach(item => {
            if (item.type === 'header') {
                html += `<li class="nav-header">${item.text}</li>`;
            } else if (item.type === 'single') {
                html += this.generateSingleMenuItem(item);
            } else if (item.type === 'dropdown') {
                html += this.generateDropdownMenuItem(item);
            }
        });

        return html;
    }

    /**
     * Genera HTML per una voce singola del menu
     */
    generateSingleMenuItem(item) {
        const activeClass = item.active ? 'active' : '';
        const badgeHtml = item.badge ?
            `<span class="nav-badge badge ${item.badge.class} me-3">${item.badge.text}</span>` : '';

        return `
            <li class="nav-item">
                <a href="${item.link || '#'}" class="nav-link ${activeClass}">
                    <i class="nav-icon bi ${item.icon}"></i>
                    <p>
                        ${item.text}
                        ${badgeHtml}
                    </p>
                </a>
            </li>
        `;
    }

    /**
     * Genera HTML per una voce dropdown del menu
     */
    generateDropdownMenuItem(item) {
        const menuOpenClass = item.menu_open ? 'menu-open' : '';
        const activeClass = item.active ? 'active' : '';
        const badgeHtml = item.badge ?
            `<span class="nav-badge badge ${item.badge.class} me-3">${item.badge.text}</span>` : '';

        let childrenHtml = '';
        if (item.children && item.children.length > 0) {
            childrenHtml = this.generateChildrenMenuHtml(item.children);
        }

        return `
            <li class="nav-item ${menuOpenClass}">
                <a href="#" class="nav-link ${activeClass}">
                    <i class="nav-icon bi ${item.icon}"></i>
                    <p>
                        ${item.text}
                        ${item.smallText ? `<small>${item.smallText}</small>` : ''}
                        ${badgeHtml}
                        <i class="nav-arrow bi bi-chevron-right"></i>
                    </p>
                </a>
                ${childrenHtml ? `<ul class="nav nav-treeview">${childrenHtml}</ul>` : ''}
            </li>
        `;
    }

    /**
     * Genera HTML per i figli di un menu dropdown
     */
    generateChildrenMenuHtml(children) {
        let html = '';

        children.forEach(child => {
            const activeClass = child.active ? 'active' : '';

            if (child.children && child.children.length > 0) {
                // Sottomenu con ulteriori figli (Level 3)
                const menuOpenClass = child.menu_open ? 'menu-open' : '';
                let subChildrenHtml = '';

                child.children.forEach(subChild => {
                    const subActiveClass = subChild.active ? 'active' : '';
                    subChildrenHtml += `
                        <li class="nav-item">
                            <a href="${subChild.link || '#'}" class="nav-link ${subActiveClass}">
                                <i class="nav-icon bi ${subChild.icon}"></i>
                                <p>${subChild.text}</p>
                            </a>
                        </li>
                    `;
                });

                html += `
                    <li class="nav-item ${menuOpenClass}">
                        <a href="#" class="nav-link ${activeClass}">
                            <i class="nav-icon bi ${child.icon}"></i>
                            <p>
                                ${child.text}
                                <i class="nav-arrow bi bi-chevron-right"></i>
                            </p>
                        </a>
                        <ul class="nav nav-treeview">${subChildrenHtml}</ul>
                    </li>
                `;
            } else {
                // Voce semplice
                html += `
                    <li class="nav-item">
                        <a href="${child.link || '#'}" class="nav-link ${activeClass}">
                            <i class="nav-icon bi ${child.icon}"></i>
                            <p>
                                ${child.text}
                                ${child.smallText ? `<small>${child.smallText}</small>` : ''}
                            </p>
                        </a>
                    </li>
                `;
            }
        });

        return html;
    }

    /**
     * Renderizza la navbar con i dati ricevuti
     */
    renderNavbar(data) {
        // Renderizza menu sinistro
        this.renderLeftNavMenu(data.leftMenu);

        // Renderizza menu destro
        this.renderRightNavMenu(data.rightMenu);
    }

    /**
     * Renderizza il menu sinistro della navbar
     */
    renderLeftNavMenu(leftMenu) {
        const navbarNav = document.querySelector('.navbar-nav:not(.ms-auto)');
        if (!navbarNav || !leftMenu) return;

        let html = '';
        leftMenu.forEach(item => {
            html += `
                <li class="nav-item">
                    <a href="${item.link}" class="nav-link">
                        ${item.icon ? `<i class="bi ${item.icon}"></i>` : ''}
                        ${item.text}
                    </a>
                </li>
            `;
        });

        navbarNav.innerHTML = html;
    }

    /**
     * Renderizza il menu destro della navbar
     */
    renderRightNavMenu(rightMenu) {
        const navbarNav = document.querySelector('.navbar-nav.ms-auto');
        if (!navbarNav || !rightMenu) return;

        let html = '';

        // Fullscreen button
        if (rightMenu.fullscreen && rightMenu.fullscreen.enabled) {
            html += this.generateFullscreenButton(rightMenu.fullscreen);
        }

        // Notifications dropdown
        if (rightMenu.notifications && rightMenu.notifications.enabled) {
            html += this.generateNotificationsDropdown(rightMenu.notifications);
        }

        // Messages dropdown
        if (rightMenu.messages && rightMenu.messages.enabled) {
            html += this.generateMessagesDropdown(rightMenu.messages);
        }

        // User menu
        if (rightMenu.user) {
            html += this.generateUserMenu(rightMenu.user);
        }

        navbarNav.innerHTML = html;
    }

    /**
     * Genera il pulsante fullscreen
     */
    generateFullscreenButton(fullscreen) {
        return `
            <li class="nav-item">
                <a class="nav-link" href="#" role="button" data-lte-toggle="fullscreen">
                    <i class="bi ${fullscreen.icon}"></i>
                </a>
            </li>
        `;
    }

    /**
     * Genera il dropdown delle notifiche
     */
    generateNotificationsDropdown(notifications) {
        let itemsHtml = '';
        if (notifications.items) {
            notifications.items.forEach((item, index) => {
                itemsHtml += `
                    ${index > 0 ? '<div class="dropdown-divider"></div>' : ''}
                    <a href="${item.link}" class="dropdown-item">
                        <i class="bi ${item.icon} me-2"></i> ${item.text}
                        <span class="float-end text-muted text-sm">${item.time}</span>
                    </a>
                `;
            });
        }

        return `
            <li class="nav-item dropdown">
                <a class="nav-link" data-bs-toggle="dropdown" href="#">
                    <i class="bi ${notifications.icon}"></i>
                    ${notifications.badge ? `<span class="navbar-badge badge text-bg-warning">${notifications.badge}</span>` : ''}
                </a>
                <div class="dropdown-menu dropdown-menu-lg dropdown-menu-end">
                    <span class="dropdown-item dropdown-header">${notifications.badge || 0} Notifications</span>
                    <div class="dropdown-divider"></div>
                    ${itemsHtml}
                    <div class="dropdown-divider"></div>
                    <a href="#" class="dropdown-item dropdown-footer">See All Notifications</a>
                </div>
            </li>
        `;
    }

    /**
     * Genera il dropdown dei messaggi
     */
    generateMessagesDropdown(messages) {
        let itemsHtml = '';
        if (messages.items) {
            messages.items.forEach((item, index) => {
                itemsHtml += `
                    ${index > 0 ? '<div class="dropdown-divider"></div>' : ''}
                    <a href="${item.link}" class="dropdown-item">
                        <div class="d-flex">
                            ${item.avatar ? `
                                <img src="${item.avatar}" alt="${item.user}" class="img-size-50 me-3 img-circle">
                            ` : ''}
                            <div>
                                <h3 class="dropdown-item-title">
                                    ${item.user}
                                    <span class="float-end text-sm text-danger"><i class="bi bi-star"></i></span>
                                </h3>
                                <p class="text-sm">${item.message}</p>
                                <p class="text-sm text-muted"><i class="bi bi-clock"></i> ${item.time}</p>
                            </div>
                        </div>
                    </a>
                `;
            });
        }

        return `
            <li class="nav-item dropdown">
                <a class="nav-link" data-bs-toggle="dropdown" href="#">
                    <i class="bi ${messages.icon}"></i>
                    ${messages.badge ? `<span class="navbar-badge badge text-bg-danger">${messages.badge}</span>` : ''}
                </a>
                <div class="dropdown-menu dropdown-menu-lg dropdown-menu-end">
                    <a href="#" class="dropdown-item">
                        ${itemsHtml}
                    </a>
                    <div class="dropdown-divider"></div>
                    <a href="#" class="dropdown-item dropdown-footer">See All Messages</a>
                </div>
            </li>
        `;
    }

    /**
     * Genera il menu utente
     */
    generateUserMenu(user) {
        return `
            <li class="nav-item dropdown user-menu">
                <a href="#" class="nav-link dropdown-toggle" data-bs-toggle="dropdown">
                    ${user.avatar ? `<img src="${user.avatar}" class="user-image rounded-circle shadow" alt="User Image">` : ''}
                    <span class="d-none d-md-inline">${user.name}</span>
                </a>
                <ul class="dropdown-menu dropdown-menu-lg dropdown-menu-end">
                    <li class="user-header text-bg-primary">
                        ${user.avatar ? `<img src="${user.avatar}" class="rounded-circle shadow" alt="User Image">` : ''}
                        <p>
                            ${user.name}
                            ${user.memberSince ? `<small>Member since ${user.memberSince}</small>` : ''}
                        </p>
                    </li>
                    ${user.links ? `
                        <li class="user-body">
                            <div class="row">
                                ${user.links.followers ? `<div class="col-4 text-center"><a href="${user.links.followers}">Followers</a></div>` : ''}
                                ${user.links.sales ? `<div class="col-4 text-center"><a href="${user.links.sales}">Sales</a></div>` : ''}
                                ${user.links.friends ? `<div class="col-4 text-center"><a href="${user.links.friends}">Friends</a></div>` : ''}
                            </div>
                        </li>
                    ` : ''}
                    ${user.actions ? `
                        <li class="user-footer">
                            ${user.actions.profile ? `<a href="${user.actions.profile}" class="btn btn-default btn-flat">Profile</a>` : ''}
                            ${user.actions.signOut ? `<a href="${user.actions.signOut}" class="btn btn-default btn-flat float-end">Sign out</a>` : ''}
                        </li>
                    ` : ''}
                </ul>
            </li>
        `;
    }

    /**
     * Reinizializza i componenti AdminLTE dopo il caricamento dinamico
     */
    initializeAdminLTEComponents() {
        // Reinizializza il treeview per il sidebar
        const treeviewMenus = document.querySelectorAll('[data-lte-toggle="treeview"]');
        treeviewMenus.forEach(menu => {
            // Rimuovi event listener esistenti se presenti
            const newMenu = menu.cloneNode(true);
            menu.parentNode.replaceChild(newMenu, menu);
        });

        // Trigger evento per indicare che AdminLTE può reinizializzare
        document.dispatchEvent(new Event('adminlte:menu:loaded'));
    }

    /**
     * Carica dinamicamente una singola sezione del menu
     */
    async loadMenuSection(section) {
        try {
            const response = await fetch(`${this.apiBaseUrl}/${section}`);
            const data = await response.json();
            return data;
        } catch (error) {
            console.error(`Errore nel caricamento della sezione ${section}:`, error);
            return null;
        }
    }

    /**
     * Aggiorna le notifiche in tempo reale
     */
    async updateNotifications() {
        try {
            const notifications = await this.loadMenuSection('notifications');
            if (notifications) {
                // Aggiorna il badge
                const badge = document.querySelector('.navbar-nav .bi-bell-fill + .navbar-badge');
                if (badge) {
                    badge.textContent = notifications.badge || '0';
                }
                // Potresti anche aggiornare il dropdown content qui
            }
        } catch (error) {
            console.error('Errore nell\'aggiornamento delle notifiche:', error);
        }
    }

    /**
     * Aggiorna i messaggi in tempo reale
     */
    async updateMessages() {
        try {
            const messages = await this.loadMenuSection('messages');
            if (messages) {
                // Aggiorna il badge
                const badge = document.querySelector('.navbar-nav .bi-chat-text-fill + .navbar-badge');
                if (badge) {
                    badge.textContent = messages.badge || '0';
                }
                // Potresti anche aggiornare il dropdown content qui
            }
        } catch (error) {
            console.error('Errore nell\'aggiornamento dei messaggi:', error);
        }
    }
}

// Inizializza il menu loader quando il DOM è pronto
document.addEventListener('DOMContentLoaded', () => {
    const menuLoader = new MenuLoader();
    menuLoader.init();

    // Opzionale: Aggiorna notifiche e messaggi ogni 30 secondi
    setInterval(() => {
        menuLoader.updateNotifications();
        menuLoader.updateMessages();
    }, 30000);

    // Esponi l'istanza globalmente per debugging o uso esterno
    window.menuLoader = menuLoader;
});