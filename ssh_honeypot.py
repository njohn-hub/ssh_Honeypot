import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading

# -----------------------------
# Logging Configuration
# -----------------------------
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
host_key = paramiko.RSAKey(filename='server.key')

# Funnel logger (records login attempts)
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Command logger (records executed commands)
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# -----------------------------
# Fake Filesystem
# -----------------------------
fake_fs = {
    "/": ["home", "etc", "var", "tmp"],
    "/home": ["corpuser1", "corpadmin"],
    "/home/corpuser1": ["notes.txt", "id_rsa", "projects"],
    "/home/corpuser1/notes.txt": """Remember to rotate SSH keys.
Also update root password.
TODO: Fix sudoers misconfiguration.
""",
    "/home/corpuser1/projects": ["jumpbox1.conf"],
    "/home/corpuser1/id_rsa": """-----BEGIN RSA PRIVATE KEY-----
FakeKeyDataHere123456789
-----END RSA PRIVATE KEY-----
""",
    "/home/corpuser1/projects/jumpbox1.conf": "Go to deeboodah.com.\n",
    "/etc": ["passwd", "shadow", "ssh"],
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
corpuser1:x:1001:1001::/home/corpuser1:/bin/bash
corpadmin:x:1002:1002::/home/corpadmin:/bin/bash
""",
    "/etc/shadow": """root:*:19847:0:99999:7:::
corpuser1:*:19847:0:99999:7:::
corpadmin:*:19847:0:99999:7:::
""",
    "/etc/ssh": ["sshd_config"],
    "/etc/ssh/sshd_config": """PermitRootLogin no
PasswordAuthentication yes
ChallengeResponseAuthentication no
""",
    "/var": ["log", "backups"],
    "/var/log": ["auth.log", "syslog"],
    "/var/log/auth.log": """Nov 22 12:33:12 auth: Failed login for root from 10.10.20.5
Nov 22 12:34:01 auth: Accepted password for corpuser1 from 192.168.1.44
""",
    "/var/log/syslog": """System boot at 12:00
Network interface eth0 up
""",
    "/tmp": []
}


# -----------------------------
# Shell Emulator
# -----------------------------
def resolve_path(cwd, path):
    """Converts relative commands into absolute paths."""
    if path.startswith("/"):
        return path
    if cwd.endswith("/"):
        return cwd + path
    return cwd + "/" + path


def list_dir(path):
    """Return directory listing."""
    return fake_fs.get(path, [])


def read_file(path):
    """Return file contents or error."""
    return fake_fs.get(path, "cat: No such file or directory\n")


def emulated_shell(channel, client_ip):
    cwd = "/home/corpuser1"

    channel.send(b'corporate-jumpbox2$ ')
    command = b""

    while True:
        char = channel.recv(1)
        if not char:
            channel.close()
            break

        channel.send(char)
        command += char

        if char == b'\r':
            channel.send(b'\n')
            cmd = command.strip().decode()

            creds_logger.info(f"Command: {cmd} from {client_ip}")

            # ---- COMMAND HANDLING ----

            if cmd == "exit":
                channel.send(b'Goodbye!\r\n')
                channel.close()
                break

            elif cmd == "pwd":
                channel.send((cwd + "\r\n").encode())

            elif cmd.startswith("cd"):
                parts = cmd.split(" ")
                if len(parts) == 1:
                    cwd = "/home/corpuser1"
                else:
                    newpath = resolve_path(cwd, parts[1])
                    if newpath in fake_fs and isinstance(fake_fs[newpath], list):
                        cwd = newpath
                    else:
                        channel.send(b"No such directory\n")

            elif cmd == "ls":
                listing = list_dir(cwd)
                for item in listing:
                    channel.send((item + "\n").encode())

            elif cmd.startswith("cat"):
                parts = cmd.split(" ")
                if len(parts) == 1:
                    channel.send(b"Usage: cat <file>\n")
                else:
                    file_path = resolve_path(cwd, parts[1])
                    content = read_file(file_path)
                    channel.send(content.encode() if isinstance(content, str) else content)

            else:
                channel.send((cmd + ": command not found\n").encode())

            channel.send(b'corporate-jumpbox2$ ')
            command = b""


# -----------------------------
# Paramiko Server Logic
# -----------------------------
class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        funnel_logger.info(f"{self.client_ip} attempted {username}:{password}")
        creds_logger.info(f"{self.client_ip}, {username}, {password}")

        if self.input_username and self.input_password:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        # No password enforcement → always succeed
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


# -----------------------------
# Client Handler
# -----------------------------
def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} connected.")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)

        server = Server(client_ip, username, password)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("Channel failed.")
            return

        channel.send(b"Hello There. Welcome!\r\n\r\n")
        emulated_shell(channel, client_ip)

    except Exception as e:
        print("ERROR:", e)
    finally:
        client.close()


# -----------------------------
# Honeypot Server Start
# -----------------------------
def honeypot(address, port, username=None, password=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100)

    print(f"SSH Honeypot listening on {address}:{port}")

    while True:
        client, addr = sock.accept()
        thread = threading.Thread(
            target=client_handle,
            args=(client, addr, username, password)
        )
        thread.start()


# -----------------------------
# RUN SERVER
# ---
