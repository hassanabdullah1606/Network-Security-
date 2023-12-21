import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_public_key_from_bytes(key_data):
    return serialization.load_pem_public_key(
        key_data,
        backend=default_backend()
    )

def save_public_key_to_file(key_data, filename):
    with open(filename, 'wb') as file:
        file.write(key_data)

def encrypt_file(filename, public_key):
    with open(filename, 'rb') as file:
        plaintext = file.read()

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def create_server(hostname='localhost', port=4443):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((hostname, port))
        sock.listen(5)
        print(f"Server is listening on {hostname}:{port}")
        conn, addr = sock.accept()
        with conn:
            print(f"Connected by {addr}")

            # Receive and save client's public key
            client_public_key_data = conn.recv(2048)  # Adjust buffer size as needed
            save_public_key_to_file(client_public_key_data, 'client_public_key.pem')
            client_public_key = load_public_key_from_bytes(client_public_key_data)
            print("Client Key have been recieved!!!")

            # Ask which file to send
            file_to_send = input("Enter the name of the file to send: ")

            # Encrypt and send file
            encrypted_file = encrypt_file(file_to_send, client_public_key)
            conn.sendall(encrypted_file)
            print(f"Encrypted file '{file_to_send}' sent to the client.")

create_server()
