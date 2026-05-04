import hashlib
import base64
import hmac
import os


class HashPasswordClient:
    def __init__(self, iteration_count: int, salt_length: int):
        self.iteration_count = iteration_count
        self.salt_length = salt_length

    def hash_password(self, raw_password: str) -> str:
        salt = os.urandom(self.salt_length)
        password_bytes = raw_password.encode('utf-8')
        hash_bytes = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=password_bytes,
            salt=salt,
            iterations=self.iteration_count
        )

        salt_b64 = base64.b64encode(salt).decode('utf-8')
        hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')

        return f'{salt_b64}${hash_b64}'


    def validate_password(self, input_password: str, hashed_password: str) -> bool:
        salt_b64, hash_b64 = hashed_password.split('$')

        salt = base64.b64decode(salt_b64)
        original_hash = base64.b64decode(hash_b64)

        password_bytes = input_password.encode('utf-8')
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt,
            self.iteration_count
        )

        return hmac.compare_digest(new_hash, original_hash)

user1 = HashPasswordClient(100_000, 16)
password1 = user1.hash_password('HelloWorld!')
print(password1)
password2 = user1.hash_password('HelloWorld235!')
print(password2)
print(user1.validate_password('HelloWorld!', password1))
print(user1.validate_password('HelloWorld!', password2))