# scanner/snmp_scanner.py - Scanner SNMP specializzato
from pysnmp.hlapi import *
import logging
from datetime import datetime
import socket


class SNMPScanner:
    """Scanner SNMP specializzato per Windows e altri OS"""

    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = logging.getLogger(__name__)

        # OID comuni per informazioni sistema
        self.system_oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysObjectID': '1.3.6.1.2.1.1.2.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'sysContact': '1.3.6.1.2.1.1.4.0',
            'sysName': '1.3.6.1.2.1.1.5.0',
            'sysLocation': '1.3.6.1.2.1.1.6.0',
            'sysServices': '1.3.6.1.2.1.1.7.0'
        }

        # OID per interfacce di rete
        self.interface_oids = {
            'ifNumber': '1.3.6.1.2.1.2.1.0',
            'ifIndex': '1.3.6.1.2.1.2.2.1.1',
            'ifDescr': '1.3.6.1.2.1.2.2.1.2',
            'ifType': '1.3.6.1.2.1.2.2.1.3',
            'ifMtu': '1.3.6.1.2.1.2.2.1.4',
            'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
            'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',
            'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
            'ifOperStatus': '1.3.6.1.2.1.2.2.1.8'
        }

        # OID per Windows specifici
        self.windows_oids = {
            'hrSystemUptime': '1.3.6.1.2.1.25.1.1.0',
            'hrSystemDate': '1.3.6.1.2.1.25.1.2.0',
            'hrSystemInitialLoadDevice': '1.3.6.1.2.1.25.1.3.0',
            'hrSystemInitialLoadParameters': '1.3.6.1.2.1.25.1.4.0',
            'hrSystemNumUsers': '1.3.6.1.2.1.25.1.5.0',
            'hrSystemProcesses': '1.3.6.1.2.1.25.1.6.0',
            'hrSystemMaxProcesses': '1.3.6.1.2.1.25.1.7.0'
        }

    def scan_device(self, ip_address, community_strings=None):
        """Esegue scansione SNMP completa su un dispositivo"""
        if community_strings is None:
            community_strings = self.config.get('snmp.community_strings', ['public'])

        self.logger.info(f"Avvio scansione SNMP su {ip_address}")

        results = {
            'ip_address': ip_address,
            'snmp_available': False,
            'community_string': None,
            'system_info': {},
            'interfaces': [],
            'windows_info': {},
            'error': None
        }

        # Testa ogni community string
        for community in community_strings:
            try:
                if self._test_snmp_access(ip_address, community):
                    results['snmp_available'] = True
                    results['community_string'] = community

                    # Raccoglie informazioni sistema
                    results['system_info'] = self._get_system_info(ip_address, community)

                    # Raccoglie informazioni interfacce
                    results['interfaces'] = self._get_interfaces_info(ip_address, community)

                    # Prova a raccogliere info Windows specifiche
                    results['windows_info'] = self._get_windows_info(ip_address, community)

                    break

            except Exception as e:
                self.logger.debug(f"Errore con community '{community}': {e}")
                continue

        if not results['snmp_available']:
            results['error'] = "SNMP non accessibile o community strings errate"
            self.logger.info(f"SNMP non disponibile su {ip_address}")
        else:
            self.logger.info(f"Scansione SNMP completata su {ip_address}")

        return results

    def _test_snmp_access(self, ip_address, community):
        """Testa accesso SNMP"""
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip_address, 161), timeout=3, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(self.system_oids['sysDescr'])),
                    lexicographicMode=False,
                    maxRows=1):

                if errorIndication:
                    return False
                if errorStatus:
                    return False

                return True

        except Exception:
            return False

        return False

    def _get_system_info(self, ip_address, community):
        """Raccoglie informazioni sistema"""
        system_info = {}

        for name, oid in self.system_oids.items():
            try:
                value = self._get_single_oid(ip_address, community, oid)
                if value:
                    system_info[name] = str(value)
            except Exception as e:
                self.logger.debug(f"Errore getting {name}: {e}")

        return system_info

    def _get_interfaces_info(self, ip_address, community):
        """Raccoglie informazioni interfacce"""
        interfaces = []

        try:
            # Prima ottieni il numero di interfacce
            if_number = self._get_single_oid(ip_address, community, self.interface_oids['ifNumber'])
            if not if_number:
                return interfaces

            num_interfaces = int(if_number)
            self.logger.debug(f"Trovate {num_interfaces} interfacce su {ip_address}")

            # Per ogni interfaccia, raccoglie informazioni
            for i in range(1, min(num_interfaces + 1, 50)):  # Limite a 50 interfacce
                interface = {'index': i}

                # Raccoglie dati per ogni OID interfaccia
                for name, base_oid in self.interface_oids.items():
                    if name == 'ifNumber':
                        continue

                    try:
                        oid = f"{base_oid}.{i}"
                        value = self._get_single_oid(ip_address, community, oid)
                        if value is not None:
                            if name == 'ifPhysAddress':
                                # Converti MAC address
                                interface[name] = self._format_mac_address(value)
                            else:
                                interface[name] = str(value)
                    except Exception as e:
                        self.logger.debug(f"Errore getting {name} per interface {i}: {e}")

                if len(interface) > 1:  # Se ha raccolto almeno un dato oltre l'index
                    interfaces.append(interface)

        except Exception as e:
            self.logger.error(f"Errore raccolta interfacce: {e}")

        return interfaces

    def _get_windows_info(self, ip_address, community):
        """Raccoglie informazioni specifiche Windows"""
        windows_info = {}

        for name, oid in self.windows_oids.items():
            try:
                value = self._get_single_oid(ip_address, community, oid)
                if value is not None:
                    windows_info[name] = str(value)
            except Exception:
                continue  # Non tutti i dispositivi supportano questi OID

        return windows_info

    def _get_single_oid(self, ip_address, community, oid):
        """Ottiene valore di un singolo OID"""
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip_address, 161), timeout=5),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False,
                    maxRows=1):

                if errorIndication:
                    raise Exception(str(errorIndication))
                if errorStatus:
                    raise Exception(f"SNMP error: {errorStatus.prettyPrint()}")

                for varBind in varBinds:
                    return varBind[1]

        except Exception as e:
            raise e

        return None

    def _format_mac_address(self, raw_mac):
        """Formatta MAC address da bytes SNMP"""
        try:
            if hasattr(raw_mac, 'asOctets'):
                octets = raw_mac.asOctets()
            else:
                octets = bytes(raw_mac)

            if len(octets) == 6:
                return ':'.join(f'{b:02x}' for b in octets).upper()
        except Exception:
            pass

        return str(raw_mac)