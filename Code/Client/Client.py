import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_private, pem_public

def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

def load_key_from_file(filename, key_type='private'):
    with open(filename, 'rb') as file:
        key_data = file.read()
        if key_type == 'private':
            return serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
        elif key_type == 'public':
            return serialization.load_pem_public_key(
                key_data,
                backend=default_backend()
            )

def decrypt_file(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def load_public_key_from_bytes(key_data):
    return serialization.load_pem_public_key(
        key_data,
        backend=default_backend()
    )

def save_public_key_to_file(key_data, filename):
    with open(filename, 'wb') as file:
        file.write(key_data)

def dump():
    encrypted_file = sock.recv(1024)  # Adjust buffer size as needed
    if not encrypted_file:
        print("No file received from server.")
        return

    # Load private key
    private_key = load_key_from_file('client_private_key.pem', key_type='private')

    # Decrypt file
    decrypted_file = decrypt_file(encrypted_file, private_key)
    with open('DecryptedTest.txt', 'wb') as file:
        file.write(decrypted_file)
    print("File received and decrypted.")

def create_client(hostname='localhost', port=4443):
    # Generate key pair and save the public key
    pem_private, pem_public = generate_key_pair()
    save_key_to_file(pem_private, 'client_private_key.pem')
    save_key_to_file(pem_public, 'client_public_key.pem')

    with socket.create_connection((hostname, port)) as sock:
        print(f"Connected to server {hostname}:{port}")

        # Send public key to server
        with open('client_public_key.pem', 'rb') as file:
            public_key_data = file.read()
            sock.sendall(public_key_data)
        print("Public key sent to server.")

        # In create_client function
        server_public_key_data = sock.recv(2048)  # Adjust buffer size as needed
        if server_public_key_data:
            save_public_key_to_file(server_public_key_data, 'server_public_key.pem')
            server_public_key = load_public_key_from_bytes(server_public_key_data)
        else:
            print("No public key received from server.")

        encrypted_file = sock.recv(1024)  # Adjust buffer size as needed
        if not encrypted_file:
            print("No file received from server.")
            return

        # Load private key
        private_key = load_key_from_file('client_private_key.pem', key_type='private')

        # Decrypt file
        decrypted_file = decrypt_file(encrypted_file, private_key)
        with open('2fa_secret.txt', 'wb') as file:
            file.write(decrypted_file)
        print("File received and decrypted.")

        encrypted_file = sock.recv(1024)  # Adjust buffer size as needed
        if not encrypted_file:
            print("No file received from server.")
            return

        # Load private key
        private_key = load_key_from_file('client_private_key.pem', key_type='private')

        # Decrypt file
        decrypted_file = decrypt_file(encrypted_file, private_key)
        with open('encryption_key.txt', 'wb') as file:
            file.write(decrypted_file)
        print("File received and decrypted.")
        

create_client()
