from cryptography.fernet import Fernet

# # Run this once to generate and save the key
# key = Fernet.generate_key()
# with open("secret.key", "wb") as key_file:
#     key_file.write(key)

def encrypt_password(password: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(token: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()
