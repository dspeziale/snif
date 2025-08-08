# Configurazione del menu con sezioni Network
MENU_STRUCTURE = {
    'dashboard': {
        'icon': 'bi bi-speedometer',
        'label': 'Dashboard Principale',
        'url': '/',
        'endpoint': 'index'
    },

    '_header_network': {
        'type': 'header',
        'label': 'NETWORK ANALYSIS'
    },

    'network_dashboard': {
        'icon': 'bi bi-diagram-3',
        'label': 'Network Dashboard',
        'url': '/network/dashboard',
        'endpoint': 'network.dashboard'
    },

    'network_scans': {
        'icon': 'bi bi-file-text',
        'label': 'Scan Manager',
        'url': None,
        'children': {
            'scans_list': {
                'icon': 'bi bi-list-ul',
                'label': 'Lista Scan',
                'url': '/network/scans',
                'endpoint': 'network.scans'
            },
            'scan_upload': {
                'icon': 'bi bi-upload',
                'label': 'Carica Scan',
                'url': '/forms',
                'endpoint': 'forms'
            }
        }
    },

    'network_hosts': {
        'icon': 'bi bi-pc-display',
        'label': 'Host Analysis',
        'url': None,
        'children': {
            'hosts_list': {
                'icon': 'bi bi-list',
                'label': 'Lista Host',
                'url': '/network/hosts',
                'endpoint': 'network.hosts'
            },
            'hosts_active': {
                'icon': 'bi bi-pc-display-horizontal',
                'label': 'Host Attivi',
                'url': '/network/hosts?status=up',
                'endpoint': 'network.hosts'
            },
            'hosts_down': {
                'icon': 'bi bi-x-circle',
                'label': 'Host Down',
                'url': '/network/hosts?status=down',
                'endpoint': 'network.hosts'
            }
        }
    },

    'network_services': {
        'icon': 'bi bi-gear',
        'label': 'Services & Ports',
        'url': None,
        'children': {
            'ports_all': {
                'icon': 'bi bi-door-open',
                'label': 'Tutte le Porte',
                'url': '/network/ports',
                'endpoint': 'network.ports'
            },
            'ports_open': {
                'icon': 'bi bi-door-open-fill',
                'label': 'Porte Aperte',
                'url': '/network/ports?state=open',
                'endpoint': 'network.ports'
            },
            'ports_filtered': {
                'icon': 'bi bi-shield',
                'label': 'Porte Filtrate',
                'url': '/network/ports?state=filtered',
                'endpoint': 'network.ports'
            }
        }
    },

    'network_security': {
        'icon': 'bi bi-shield-exclamation',
        'label': 'Security Analysis',
        'url': None,
        'children': {
            'vulnerabilities': {
                'icon': 'bi bi-bug',
                'label': 'Vulnerabilità',
                'url': '/network/vulnerabilities',
                'endpoint': 'network.vulnerabilities'
            },
            'vuln_critical': {
                'icon': 'bi bi-exclamation-triangle-fill',
                'label': 'Critiche',
                'url': '/network/vulnerabilities?severity=critical',
                'endpoint': 'network.vulnerabilities'
            },
            'vuln_high': {
                'icon': 'bi bi-exclamation-triangle',
                'label': 'Elevate',
                'url': '/network/vulnerabilities?severity=high',
                'endpoint': 'network.vulnerabilities'
            }
        }
    },

    'network_search': {
        'icon': 'bi bi-search',
        'label': 'Ricerca Avanzata',
        'url': '/network/search',
        'endpoint': 'network.search'
    },

    '_header_tools': {
        'type': 'header',
        'label': 'TOOLS & UTILITIES'
    },

    'widgets': {
        'icon': 'bi bi-bar-chart',
        'label': 'Grafici & Statistiche',
        'url': '/widgets',
        'endpoint': 'widgets'
    },

    'tables': {
        'icon': 'bi bi-table',
        'label': 'Tabelle Dati',
        'url': '/tables',
        'endpoint': 'tables'
    },

    'system_tools': {
        'icon': 'bi bi-tools',
        'label': 'Strumenti Sistema',
        'url': None,
        'children': {
            'forms': {
                'icon': 'bi bi-file-earmark-text',
                'label': 'Test & Config',
                'url': '/forms',
                'endpoint': 'forms'
            },
            'about': {
                'icon': 'bi bi-info-circle',
                'label': 'Info Sistema',
                'url': '/about',
                'endpoint': 'about'
            }
        }
    },

    '_header_examples': {
        'type': 'header',
        'label': 'EXAMPLES'
    },

    'examples': {
        'icon': 'bi bi-collection',
        'label': 'Esempi',
        'url': None,
        'children': {
            'example_1': {
                'icon': 'bi bi-1-circle',
                'label': 'Esempio 1',
                'url': '#'
            },
            'example_2': {
                'icon': 'bi bi-2-circle',
                'label': 'Esempio 2',
                'url': '#'
            }
        }
    }
}