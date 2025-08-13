import select

import paramiko
import time
import getpass


class SSHManager:
    def __init__(self, hostname, username, password=None, port=22):
        self.hostname = hostname
        self.username = username
        self.password = password or getpass.getpass(f"Password per {username}@{hostname}: ")
        self.ssh_client = None
        self.sftp_client = None
        self.port = port

    def connetti(self):
        """Stabilisce la connessione SSH"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.ssh_client.connect(
                hostname=self.hostname,
                username=self.username,
                password=self.password,
                timeout=15,port=self.port
            )
            print(f"✓ Connesso a {self.hostname}")
            return True

        except Exception as e:
            print(f"✗ Errore connessione: {e}")
            return False

    def esegui_comando(self, comando, timeout=30):
        """Esegue un singolo comando"""
        if not self.ssh_client:
            print("Nessuna connessione attiva")
            return None

        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(comando, timeout=timeout)

            # Attende completamento
            exit_code = stdout.channel.recv_exit_status()

            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()

            return {
                'comando': comando,
                'output': output,
                'error': error,
                'exit_code': exit_code,
                'successo': exit_code == 0
            }

        except Exception as e:
            return {
                'comando': comando,
                'output': '',
                'error': str(e),
                'exit_code': -1,
                'successo': False
            }

    def esegui_script(self, comandi, ferma_su_errore=True):
        """Esegue una lista di comandi in sequenza"""
        risultati = []

        for comando in comandi:
            print(f"\n> {comando}")
            risultato = self.esegui_comando(comando)
            risultati.append(risultato)

            if risultato['output']:
                print(risultato['output'])

            if risultato['error']:
                print(f"ERRORE: {risultato['error']}")

            if not risultato['successo'] and ferma_su_errore:
                print("Interruzione script a causa di errore")
                break

        return risultati

    def carica_file(self, file_locale, file_remoto):
        """Carica un file sul server"""
        try:
            if not self.sftp_client:
                self.sftp_client = self.ssh_client.open_sftp()

            self.sftp_client.put(file_locale, file_remoto)
            print(f"✓ File caricato: {file_locale} -> {file_remoto}")
            return True

        except Exception as e:
            print(f"✗ Errore caricamento file: {e}")
            return False

    def disconnetti(self):
        """Chiude tutte le connessioni"""
        if self.sftp_client:
            self.sftp_client.close()
        if self.ssh_client:
            self.ssh_client.close()
        print("Disconnesso")


# Esempio di utilizzo avanzato
if __name__ == "__main__":
    # Configurazione
    server = SSHManager("torraccia.iliadboxos.it", port=57422,
                        username="root", password='tiboxes.org')

    if server.connetti():
        # Esegue comandi singoli
        risultato = server.esegui_comando("uname -a")
        print(f"Sistema: {risultato['output']}")

        # Esegue script di comandi
        script_comandi = [
            # "pwd",
            # "ls -la",
            # "df -h",
            # "free -m",
            # "cd /mnt/condivisione",
            "nmap -T5 -sn 192.168.1.0/24 -oX all.sn.xml"
            # "ls -la",
            # "ps aux | head -10"
        ]

        print("\n" + "=" * 50)
        print("ESECUZIONE SCRIPT")
        print("=" * 50)

        risultati = server.esegui_script(script_comandi)

        # Disconnessione
        server.disconnetti()