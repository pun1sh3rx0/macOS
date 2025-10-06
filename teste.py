import getpass
import socket
import subprocess

# Obtém o nome do usuário
print(f"Usuário: {getpass.getuser()}")

# Obtém o hostname
print(f"Hostname: {socket.gethostname()}")

# Obtém o endereço IP da interface en0
ip = subprocess.run("ifconfig en0 | grep 'inet ' | awk '{print $2}'", shell=True, capture_output=True, text=True).stdout.strip()
print(f"Endereço IP: {ip}")
