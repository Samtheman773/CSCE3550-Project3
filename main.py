# Samuel Alvizo
# sa1369


import base64
import json
import sqlite3
import time
import uuid
import datetime
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from argon2 import PasswordHasher
import jwt

# Constants
NOT_MY_KEY = b'ylcg3o6pv84aehqj'

# Helper functions
def encode_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def encrypt_with_aes(key: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt_with_aes(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

def serialize_key_to_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

def deserialize_pem_to_key(pem_bytes):
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None
    )


def get_valid_private_keys():
    current_time = int(datetime.datetime.utcnow().timestamp())
    query = "SELECT kid, key FROM keys WHERE exp > ?"

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn1:
        cursor = conn1.execute(query, (current_time,))
        key_data = cursor.fetchall()

    # Deserialize the keys and pair with their respective kid
    keys = [(data[0], deserialize_pem_to_key(decrypt_with_aes(NOT_MY_KEY, data[1]))) for data in key_data]
    return keys


def get_private_key_from_db(expired=False):
    current_time = int(datetime.datetime.utcnow().timestamp())

    # Query to fetch based on expiration status
    if expired:
        query = "SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1"
    else:
        query = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1"

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn2:
        cursor = conn2.execute(query, (current_time,))
        key_data = cursor.fetchone()

    # Deserialize the key and pair with its kid if found
    if key_data:
        # Ensure the 'exp' value retrieved is in the expected format (integer)
        exp_value = key_data[2]
        if not isinstance(exp_value, int):
            print(f"Unexpected 'exp' value type: {type(exp_value)} - Value: {exp_value}")

        return key_data[0], deserialize_pem_to_key(decrypt_with_aes(NOT_MY_KEY, key_data[1]))
    return None, None


def get_user_id_from_username(username):
    with sqlite3.connect('totally_not_my_privateKeys.db') as connGetID:
        cursor = connGetID.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()

    if user_data:
        return user_data[0]
    return None


# Create and initialize DB
conn = sqlite3.connect('totally_not_my_privateKeys.db')  # Create DB

conn.execute('CREATE TABLE IF NOT EXISTS keys('
             'kid INTEGER PRIMARY KEY AUTOINCREMENT, '
             'key BLOB NOT NULL, '
             'exp INTEGER NOT NULL)')   # Create keys table in DB

conn.execute('CREATE TABLE IF NOT EXISTS users('
             'id INTEGER PRIMARY KEY AUTOINCREMENT, '
             'username TEXT NOT NULL UNIQUE, '
             'password_hash TEXT NOT NULL, '
             'email TEXT UNIQUE, '
             'date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, '
             'last_login TIMESTAMP)')

conn.execute('CREATE TABLE IF NOT EXISTS auth_logs('
             'id INTEGER PRIMARY KEY AUTOINCREMENT, '
             'request_ip TEXT NOT NULL, '
             'request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, '
             'user_id INTEGER, '
             'FOREIGN KEY(user_id) REFERENCES users(id))')


conn.commit()

# Create and serialize keys
init_unexpired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
init_expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
init_unexpired_key_PEM = serialize_key_to_pem(init_unexpired_key)
init_expired_key_PEM = serialize_key_to_pem(init_expired_key)

now = int(datetime.datetime.utcnow().timestamp())
hour_from_now = now + 3600

# Insert the serialized and encrypted keys into the DB
encrypted_unexpired_key = encrypt_with_aes(NOT_MY_KEY, init_unexpired_key_PEM.encode('utf-8'))
encrypted_expired_key = encrypt_with_aes(NOT_MY_KEY, init_expired_key_PEM.encode('utf-8'))

conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_expired_key, int(now-36000)))
conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_expired_key, int(now-36000)))
conn.commit()

hostName = "localhost"  # Use localhost for server
serverPort = 8080  # Use port 8080 for server

class RateLimiter:
    def __init__(self, max_requests, per_seconds):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self.request_times = {}

    def allow_request(self, ip):
        current_time = time.time()
        if ip not in self.request_times:
            self.request_times[ip] = [current_time]
            return True
        else:
            # Filter out old timestamps
            self.request_times[ip] = [t for t in self.request_times[ip] if current_time - t < self.per_seconds]
            if len(self.request_times[ip]) < self.max_requests:
                self.request_times[ip].append(current_time)
                return True
            else:
                return False


rate_limiter = RateLimiter(max_requests=10, per_seconds=1)

# Configure web server requests/actions
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            client_ip = self.client_address[0]

            # Check with the rate limiter
            if not rate_limiter.allow_request(client_ip):
                self.send_response(429, "Too Many Requests")
                self.end_headers()
                return
            
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes("Test response", "utf-8"))
                return

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            auth_data = json.loads(post_data.decode('utf-8'))

            # Authentication logic
            kid, key = get_private_key_with_kid_from_db('expired' in params)

            if not key:
                self.send_response(500, "Unable to fetch private key")
                self.end_headers()
                return

            headers = {"kid": str(kid)}
            token_payload = {"user": auth_data.get('username'),
                            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
            key_pem = serialize_key_to_pem(key)
            encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)

            # Log the successful request
            print(f"Logging /auth request for IP: {client_ip}")
            user_id = get_user_id_from_username(auth_data.get('username'))
            request_ip = self.client_address[0]
            request_timestamp = datetime.datetime.utcnow()

            try:
                with sqlite3.connect('totally_not_my_privateKeys.db') as connLog:
                    connLog.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
                                    (request_ip, request_timestamp, user_id))
                    connLog.commit()
            except sqlite3.Error as e:
                print(f"Error logging /auth request: {e}")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return


    


        elif parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data.decode('utf-8'))

            # Generate a secure password using UUIDv4
            generated_password = str(uuid.uuid4())

            # Hash the password using Argon2
            ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
            hashed_password = ph.hash(generated_password)

            # Store the user details and hashed password in the users table
            with sqlite3.connect('totally_not_my_privateKeys.db') as connRegister:
                connRegister.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                                     (user_data['username'], user_data['email'], hashed_password))
                connRegister.commit()

            # Return the generated password to the user
            response_data = {"password": generated_password}
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

        else:
            self.send_response(405)
            self.end_headers()
            return

    def do_GET(self):  # Define GET request action
        if self.path == "/.well-known/jwks.json":  # Check if requested path is correct
            valid_keys_with_kid = get_all_private_keys()
            jwks = {"keys": []}
            # Create list of keys
            for kid, key in valid_keys_with_kid:
                private_numbers = key.private_numbers()
                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(private_numbers.public_numbers.n),
                    "e": int_to_base64(private_numbers.public_numbers.e)
                })
            # Return list of keys
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)  # Define web server
    
    print("HTTP Server running on Localhost port 8080...")  # Print message indicating server start

    try:
        webServer.serve_forever()  # Start web server
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()  # Close web server
        print("Server stopped.")