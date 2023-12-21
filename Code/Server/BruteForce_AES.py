from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def AES_Encryption(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return cipher.iv, ct_bytes

def Is_Valid_Format(data):
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def Brute_Force_Attack(ct, iv, Maximum_Attempts=1000):
    Attempts = 0
    while Attempts < Maximum_Attempts:
        Attempts += 1
        Guesses_Key = get_random_bytes(16)  # AES 128-bit key
        try:
            cipher = AES.new(Guesses_Key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            if Is_Valid_Format(pt):
                print(f"Decryption successful on attempt {Attempts}. Key: {Guesses_Key.hex()}")
                return pt
        except (ValueError, KeyError):
            continue

    print(f"Failed to decrypt after {Maximum_Attempts} Attempts.")
    return None
# Encrypt a sample message
Original_Key = get_random_bytes(16)  # AES 128-bit key
print(f"Original Key: {Original_Key}")
iv, encrypted_data = AES_Encryption("Trying Brute Force", Original_Key)

# Attempt to brute force decrypt
decrypted_data = Brute_Force_Attack(encrypted_data, iv, Maximum_Attempts=200000)

if decrypted_data:
    print(f"Decrypted Data: {decrypted_data.decode('utf-8')}")
else:
    print("Decryption failed.")
