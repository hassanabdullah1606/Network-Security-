import pyotp
import time
def Brute_Force_TOTP(Secret_Key, Attempt_Duration=30, token_length=6):
    Start_Time = time.time()
    Attempts = 0
    Valid_Token = pyotp.TOTP(Secret_Key).now()

    print(f"Valid TOTP Token: {Valid_Token}")
    while time.time() - Start_Time < Attempt_Duration:
        # Generating Random Tokens
        Guesses = f"{pyotp.random_base32()[:token_length]}"
        Attempts += 1
        if Guesses == Valid_Token:
            print(f"Token cracked in {Attempts} Attempts!")
            return True
    print(f"Failed to crack the token in {Attempts} Attempts within {Attempt_Duration} seconds.")
    return False
# Example usage
Secret_Key = pyotp.random_base32()  # Generate a Secret_Key for TOTP
Brute_Force_TOTP(Secret_Key, Attempt_Duration=30, token_length=6)
