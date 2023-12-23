import time
import pyotp

def Test_Reply_Attack():
    # Generate a TOTP Token
    Secret = pyotp.random_base32()
    totp = pyotp.TOTP(Secret)
    Token = totp.now()
    print(f"The Token is as:", Token)
    # First verification (should succeed)
    Verification_Result = totp.verify(Token)
    print(f"First verification: {'Success' if Verification_Result else 'Failure'}")

    # Wait for the TOTP to expire (e.g., 30 seconds for standard TOTP)
    time.sleep(30)
    # Second verification with the same Token (should fail)
    Verification_Result = totp.verify(Token)
    print(f"Second verification: {'Success' if Verification_Result else 'Failure'}")
Test_Reply_Attack()
