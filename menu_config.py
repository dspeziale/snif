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

}