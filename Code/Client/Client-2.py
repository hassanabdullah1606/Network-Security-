import socket, subprocess, os, base64, pyotp, qrcode, time, psutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def prompt_for_action():
    print("Select an action:")
    print("1: Use a File")
    print("2: Share File")
    print("3: Recieve File")
    print("4: Create connection")
    print("#: To Exit")
    return input("Enter your choice (1, 2, or 3): ")

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

def Create_Connection(hostname='localhost', port=4443):
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
        

def Send_File(hostname='localhost', port=4443):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((hostname, port))
        sock.listen(5)
        print(f"Server is listening on {hostname}:{port}")
        conn, addr = sock.accept()
        with conn:
            print(f"Connected by {addr}")

            # Ask which file to send
            file_to_send = input("Enter the name of the file to send: ")
            # Get the filename from the path
            filename = os.path.basename(file_to_send)

            server_public_key = load_key_from_file('server_public_key.pem', key_type='public')
            # Encrypt and send filename, file data
            encrypted_file = encrypt_file(file_to_send, server_public_key)
            sock.sendall(filename.encode('utf-8') + b'\n' + encrypted_file)
            print(f"File '{filename}' sent to the server.")
            
def Receive_File(hostname='localhost', port=4443):
    with socket.create_connection((hostname, port)) as sock:
        print(f"Connected to server {hostname}:{port}")
        data = sock.recv(1024)  # Adjust buffer size as needed
        if not data:
            print("No file received from server.")
            return

        # Load private key
        private_key = load_key_from_file('client_private_key.pem', key_type='private')

        # Separate filename and encrypted file content
        filename, encrypted_file = data.split(b'\n', 1)
        filename = filename.decode('utf-8')

        # Decrypt file content
        decrypted_file = decrypt_file(encrypted_file, private_key)

        # Save the received file with the original filename
        with open(filename, 'wb') as file:
            file.write(decrypted_file)
        print(f"File '{filename}' received and decrypted.")


#--------------------------------!!!!-------- 2FA  --------!!!!!----------------------------#

def Save_Data_To_File(data, filename):
    with open(filename, "w") as file:
        file.write(data)

def Load_Data_From_File(filename):
    with open(filename, "r") as file:
        return file.read()

def Encrypt_File(File_Path, key, token, secret):
    if not Verify_TOTP_Token(token, secret):
        raise Exception("Invalid 2FA token")

    with open(File_Path, 'r') as file:
        file_data = file.read()

    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(file_data.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')

    Encrypted_File_Path = File_Path
    Save_Data_To_File(iv + '\n' + ct, Encrypted_File_Path)
    return Encrypted_File_Path

def Decrypt_File(Encrypted_File_Path, key, token, secret):
    if not Verify_TOTP_Token(token, secret):
        raise Exception("Invalid 2FA token")

    iv, ct = Load_Data_From_File(Encrypted_File_Path).split('\n', 1)
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)

    Decrypted_File_Path = Encrypted_File_Path
    Save_Data_To_File(pt.decode('utf-8'), Decrypted_File_Path)
    return Decrypted_File_Path
    
def Generate_AES_Key():
    key = get_random_bytes(16)  # AES key length 16 bytes (128 bit)
    print(key)
    return base64.b64encode(key).decode('utf-8')

def Load_Key(b64key):
    return base64.b64decode(b64key)

def Encrypt_Data_AES(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def Decrypt_Data_AES(iv, ct, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')


def Generate_2FA_Key():
    return pyotp.random_base32()

def Get_TOTP_Token(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

def Verify_TOTP_Token(token, secret):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def Encrypt_Data_With_2FA(data, key, token, secret):
    if Verify_TOTP_Token(token, secret):
        return Encrypt_Data_AES(data, key)
    else:
        raise Exception("Invalid 2FA token")

def Decrypt_Data_with_2FA(iv, ct, key, token, secret):
    if Verify_TOTP_Token(token, secret):
        return Decrypt_Data_AES(iv, ct, key)
    else:
        raise Exception("Invalid 2FA token")
# Add functions to save and load the 2FA secret
def Save_2FA_Key(secret, filename="2fa_secret.txt"):
    with open(filename, "w") as file:
        file.write(secret)

def Load_2FA_Key(filename="2fa_secret.txt"):
    if os.path.exists(filename):
        with open(filename, "r") as file:
            return file.read()
    return None

def Is_File_Empty(File_Path):
    """Check if file is empty by reading its size."""
    return os.path.getsize(File_Path) == 0

def File_Path_Prompt():
    for attempt in range(3):
        File_Path = input("Enter the path of the file: ")
        if os.path.exists(File_Path):
            return File_Path
        else:
            user_choice = input("File not found. Do you want to create it? (yes/no): ")
            if user_choice.lower() == 'yes':
                open(File_Path, 'w').close()  # Create an empty file
                return File_Path
            elif user_choice.lower() == 'no':
                continue
            else:
                print("Invalid choice.")
    raise Exception("File not found after 3 attempts.")

def Edit_and_Encrypt(File_Path, key, secret):
    token = Token_Prompt()
    initially_empty = Is_File_Empty(File_Path)

    if initially_empty:
        Decrypted_File_Path = File_Path
    else:
        Decrypted_File_Path = Decrypt_File(File_Path, key, token, secret)

    # Open the file in Notepad and wait for the process to finish
    notepad_process = subprocess.Popen(['notepad', Decrypted_File_Path])
    notepad_process.wait()  # Wait for the Notepad process to exit

    # Check if the file is still empty after editing
    file_now_empty = Is_File_Empty(Decrypted_File_Path)

    # Re-encrypt the file if it was initially not empty or if it's not empty now
    if not initially_empty or not file_now_empty:
        token = Token_Prompt()
        Encrypt_File(Decrypted_File_Path, key, token, secret)
    print(f"File '{File_Path}' re-encrypted and stored.")

def Token_Prompt():
    for attempt in range(3):
        token = input("Enter the token from Microsoft Authenticator: ")
        if token:
            return token
        else:
            print("Invalid token.")
    raise Exception("Invalid token after 3 attempts.")


def File_Management():
    # AES key management
    if not os.path.exists("encryption_key.txt"):
        encryption_key = Generate_AES_Key()
        Save_Data_To_File(encryption_key, "encryption_key.txt")
    else:
        encryption_key = Load_Data_From_File("encryption_key.txt")

    key = Load_Key(encryption_key)

    # 2FA setup - load existing secret or generate a new one
    if not os.path.exists("2fa_secret.txt"):
        secret = Generate_2FA_Key()
        Save_2FA_Key(secret, "2fa_secret.txt")
        print("New 2FA secret generated and saved.")
        
        # Display QR code for first-time setup
        print("Scan the QR code using Microsoft Authenticator to set up 2FA:")
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri("Client2@NS.edu.pk", issuer_name="Client_2")
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.show()
    else:
        secret = Load_2FA_Key("2fa_secret.txt")

    try:
        File_Path = File_Path_Prompt()
        secret = Load_2FA_Key("2fa_secret.txt")
        key = Load_Key(Load_Data_From_File("encryption_key.txt"))
        Edit_and_Encrypt(File_Path, key, secret)

    except Exception as e:
        print(f"Error: {e}")


def main():
    action = 'a'
    while(action != '#'):
        action = prompt_for_action()
        if action == '1':
            File_Management()
        elif action == '2':
            Send_File()
        elif action == '3':
            Receive_File()
        elif action == '4':
            Create_Connection()
        elif action == '#':
            break




if __name__ == "__main__":
    main()