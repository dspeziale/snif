# Configurazione del menu con sezioni Network e SNMP - STRUTTURA CORRETTA
MENU_STRUCTURE = {
    # ===========================
    # HEADER - ANALISI NETWORK
    # ===========================
    '_header_network': {
        'type': 'header',
        'label': 'NETWORK ANALYSIS'
    },

    # Dashboard principale
    'network_dashboard': {
        'icon': 'bi bi-diagram-3',
        'label': 'Network Dashboard',
        'url': '/network/dashboard',
        'endpoint': 'network.dashboard'
    },

    # ===========================
    # GESTIONE SCAN
    # ===========================
    'network_scans': {
        'icon': 'bi bi-file-text',
        'label': 'Gestione Scan',
        'url': None,  # ← Importante: None per abilitare dropdown
        'children': {
            'scans_list': {
                'icon': 'bi bi-list-ul',
                'label': 'Lista Scan',
                'url': '/network/scans',
                'endpoint': 'network.scans'
            },
            'scan_new': {
                'icon': 'bi bi-plus-circle',
                'label': 'Nuovo Scan',
                'url': '/forms',  # Se esiste una pagina per creare nuovi scan
                'endpoint': 'forms'
            }
        }
    },

    # ===========================
    # ANALISI HOST
    # ===========================
    'network_hosts': {
        'icon': 'bi bi-pc-display',
        'label': 'Analisi Host',
        'url': None,  # ← Importante: None per abilitare dropdown
        'children': {
            'hosts_all': {
                'icon': 'bi bi-list',
                'label': 'Tutti gli Host',
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
                'label': 'Host Inattivi',
                'url': '/network/hosts?status=down',
                'endpoint': 'network.hosts'
            },
            'hosts_with_vulnerabilities': {
                'icon': 'bi bi-bug-fill',
                'label': 'Host con Vulnerabilità',
                'url': '/network/hosts?vulnerabilities=1',
                'endpoint': 'network.hosts'
            }
        }
    },

    # ===========================
    # SERVIZI E PORTE
    # ===========================
    'network_services': {
        'icon': 'bi bi-gear',
        'label': 'Servizi e Porte',
        'url': None,  # ← Importante: None per abilitare dropdown
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
            'ports_closed': {
                'icon': 'bi bi-door-closed',
                'label': 'Porte Chiuse',
                'url': '/network/ports?state=closed',
                'endpoint': 'network.ports'
            },
            'ports_filtered': {
                'icon': 'bi bi-shield',
                'label': 'Porte Filtrate',
                'url': '/network/ports?state=filtered',
                'endpoint': 'network.ports'
            },
            'services_common': {
                'icon': 'bi bi-star',
                'label': 'Servizi Comuni',
                'url': '/network/ports?common=1',
                'endpoint': 'network.ports'
            }
        }
    },

    # ===========================
    # ANALISI SICUREZZA
    # ===========================
    'network_security': {
        'icon': 'bi bi-shield-exclamation',
        'label': 'Analisi Sicurezza',
        'url': None,  # ← Importante: None per abilitare dropdown
        'children': {
            'vulnerabilities_all': {
                'icon': 'bi bi-bug',
                'label': 'Tutte le Vulnerabilità',
                'url': '/network/vulnerabilities',
                'endpoint': 'network.vulnerabilities'
            },
            'vuln_critical': {
                'icon': 'bi bi-exclamation-triangle-fill',
                'label': 'Vulnerabilità Critiche',
                'url': '/network/vulnerabilities?severity=critical',
                'endpoint': 'network.vulnerabilities'
            },
            'vuln_high': {
                'icon': 'bi bi-exclamation-triangle',
                'label': 'Vulnerabilità Elevate',
                'url': '/network/vulnerabilities?severity=high',
                'endpoint': 'network.vulnerabilities'
            },
            'vuln_medium': {
                'icon': 'bi bi-exclamation-circle',
                'label': 'Vulnerabilità Medie',
                'url': '/network/vulnerabilities?severity=medium',
                'endpoint': 'network.vulnerabilities'
            },
            'vuln_low': {
                'icon': 'bi bi-info-circle',
                'label': 'Vulnerabilità Basse',
                'url': '/network/vulnerabilities?severity=low',
                'endpoint': 'network.vulnerabilities'
            }
        }
    },

    # ===========================
    # HEADER - ANALISI SNMP
    # ===========================
    '_header_snmp': {
        'type': 'header',
        'label': 'SNMP ANALYSIS'
    },

    # Dashboard SNMP
    'snmp_dashboard': {
        'icon': 'bi bi-router',
        'label': 'SNMP Dashboard',
        'url': '/network/snmp',
        'endpoint': 'network.snmp_dashboard'
    },

    # ===========================
    # INVENTARIO SNMP
    # ===========================
    'snmp_inventory': {
        'icon': 'bi bi-clipboard-data',
        'label': 'Inventario SNMP',
        'url': None,  # ← Importante: None per abilitare dropdown
        'children': {
            'snmp_services': {
                'icon': 'bi bi-gear-wide-connected',
                'label': 'Servizi Sistema',
                'url': '/network/snmp/services',
                'endpoint': 'network.snmp_services'
            },
            'snmp_processes': {
                'icon': 'bi bi-cpu',
                'label': 'Processi Attivi',
                'url': '/network/snmp/processes',
                'endpoint': 'network.snmp_processes'
            },
            'snmp_software': {
                'icon': 'bi bi-box-seam',
                'label': 'Software Installato',
                'url': '/network/snmp/software',
                'endpoint': 'network.snmp_software'
            },
            'snmp_users': {
                'icon': 'bi bi-people',
                'label': 'Utenti Sistema',
                'url': '/network/snmp/users',
                'endpoint': 'network.snmp_users'
            }
        }
    },

    # ===========================
    # RETE SNMP
    # ===========================
    'snmp_network': {
        'icon': 'bi bi-diagram-2',
        'label': 'Rete SNMP',
        'url': None,  # ← Importante: None per abilitare dropdown
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

    # ===========================
    # ANALISI SNMP
    # ===========================
    'snmp_analysis': {
        'icon': 'bi bi-graph-up',
        'label': 'Analisi SNMP',
        'url': None,  # ← Importante: None per abilitare dropdown
        'children': {
            'snmp_overview': {
                'icon': 'bi bi-hdd-network',
                'label': 'Panoramica SNMP',
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
    # HEADER - STRUMENTI
    # ===========================
    '_header_tools': {
        'type': 'header',
        'label': 'STRUMENTI'
    },

    # ===========================
    # RICERCA E STRUMENTI
    # ===========================
    'network_tools': {
        'icon': 'bi bi-tools',
        'label': 'Strumenti di Rete',
        'url': None,  # ← Importante: None per abilitare dropdown
        'children': {
            'network_search': {
                'icon': 'bi bi-search',
                'label': 'Ricerca Avanzata',
                'url': '/network/search',
                'endpoint': 'network.search'
            },
            'network_export': {
                'icon': 'bi bi-download',
                'label': 'Export Dati',
                'url': '/network/export',
                'endpoint': 'network.export'  # Se esiste
            }
        }
    },

    # ===========================
    # CONFIGURAZIONI
    # ===========================
    'system_config': {
        'icon': 'bi bi-gear-fill',
        'label': 'Configurazioni',
        'url': None,  # ← Importante: None per abilitare dropdown
        'children': {
            'settings': {
                'icon': 'bi bi-sliders',
                'label': 'Impostazioni',
                'url': '/settings',
                'endpoint': 'settings'  # Se esiste
            },
            'about': {
                'icon': 'bi bi-info-circle',
                'label': 'Informazioni',
                'url': '/about',
                'endpoint': 'about'
            }
        }
    }
}