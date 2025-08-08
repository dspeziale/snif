# Configurazione del menu con sezioni Network e SNMP
MENU_STRUCTURE = {
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

    # ===========================
    # NUOVA SEZIONE SNMP
    # ===========================
    '_header_snmp': {
        'type': 'header',
        'label': 'SNMP ANALYSIS'
    },

    'snmp_dashboard': {
        'icon': 'bi bi-router',
        'label': 'SNMP Dashboard',
        'url': '/network/snmp',
        'endpoint': 'network.snmp_dashboard'
    },

    'snmp_inventory': {
        'icon': 'bi bi-clipboard-data',
        'label': 'Inventario SNMP',
        'url': None,
        'children': {
            'snmp_services': {
                'icon': 'bi bi-gear-wide-connected',
                'label': 'Servizi Sistema',
                'url': '/network/snmp/services',
                'endpoint': 'network.snmp_services'
            },
            'snmp_software': {
                'icon': 'bi bi-box-seam',
                'label': 'Software Installato',
                'url': '/network/snmp/software',
                'endpoint': 'network.snmp_software'
            },
            'snmp_processes': {
                'icon': 'bi bi-cpu',
                'label': 'Processi Attivi',
                'url': '/network/snmp/processes',
                'endpoint': 'network.snmp_processes'
            },
            'snmp_users': {
                'icon': 'bi bi-people',
                'label': 'Utenti Sistema',
                'url': '/network/snmp/users',
                'endpoint': 'network.snmp_users'
            }
        }
    },

    'snmp_network': {
        'icon': 'bi bi-diagram-2',
        'label': 'Rete SNMP',
        'url': None,
        'children': {
            'snmp_interfaces': {
                'icon': 'bi bi-ethernet',
                'label': 'Interfacce di Rete',
                'url': '/network/snmp/interfaces',
                'endpoint': 'network.snmp_interfaces'
            },
            'snmp_connections': {
                'icon': 'bi bi-diagram-3',
                'label': 'Connessioni Attive',
                'url': '/network/snmp/connections',
                'endpoint': 'network.snmp_connections'
            },
            'snmp_shares': {
                'icon': 'bi bi-folder-shared',
                'label': 'Condivisioni',
                'url': '/network/snmp/shares',
                'endpoint': 'network.snmp_shares'
            }
        }
    },

    'snmp_analysis': {
        'icon': 'bi bi-graph-up',
        'label': 'Analisi SNMP',
        'url': None,
        'children': {
            'snmp_hosts_summary': {
                'icon': 'bi bi-hdd-network',
                'label': 'Riepilogo Host',
                'url': '/network/hosts?snmp=1',
                'endpoint': 'network.hosts'
            },
            'snmp_statistics': {
                'icon': 'bi bi-bar-chart',
                'label': 'Statistiche Dettagliate',
                'url': '/network/snmp/stats',
                'endpoint': 'network.snmp_statistics'
            },
            'snmp_reports': {
                'icon': 'bi bi-file-earmark-bar-graph',
                'label': 'Report SNMP',
                'url': '/network/snmp/reports',
                'endpoint': 'network.snmp_reports'
            }
        }
    },

    # ===========================
    # SEZIONI ESISTENTI
    # ===========================
    'network_search': {
        'icon': 'bi bi-search',
        'label': 'Ricerca Avanzata',
        'url': '/network/search',
        'endpoint': 'network.search'
    },

}