import pyotp
import qrcode

# Generate a TOTP secret for a user
totp_secret = pyotp.random_base32()

# Generate a URI for the QR code
totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri("user@example.com", issuer_name="YourServiceName")

# Generate and display the QR code (to be scanned with Microsoft Authenticator)
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

# Function to verify the TOTP token (Password from Microsoft Authenticator)
def verify_totp(token, secret):
    """
    Verifies a TOTP token (password) against the given secret.

    :param token: The TOTP token to verify (password from the Authenticator app).
    :param secret: The secret key associated with the user's TOTP.
    :return: True if the token is valid, False otherwise.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

# Example usage
user_token = input("Enter the token from Microsoft Authenticator: ")
is_valid = verify_totp(user_token, totp_secret)

if is_valid:
    print("Token is valid.")
else:
    print("Invalid token.")
