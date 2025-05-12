import os
import tempfile
import pytest
from crypto_utils import (
    derive_key,
    encrypt_text,
    decrypt_text,
    encrypt_file,
    decrypt_file
)

# Constants for tests
PASSPHRASE = "test_passphrase"
PLAINTEXT = "This is a secret message."

def test_derive_key_returns_bytes():
    salt = os.urandom(16)
    key = derive_key(PASSPHRASE, salt)
    assert isinstance(key, bytes)
    assert len(key) == 44  # Fernet keys are always 44 bytes when base64-encoded

def test_encrypt_decrypt_text_returns_original():
    encrypted = encrypt_text(PLAINTEXT, PASSPHRASE)
    decrypted = decrypt_text(encrypted, PASSPHRASE)
    assert decrypted == PLAINTEXT

def test_encrypt_text_produces_different_output_each_time():
    encrypted1 = encrypt_text(PLAINTEXT, PASSPHRASE)
    encrypted2 = encrypt_text(PLAINTEXT, PASSPHRASE)
    assert encrypted1 != encrypted2  # Different salts → different ciphertext

def test_decrypt_text_with_wrong_passphrase_raises():
    encrypted = encrypt_text(PLAINTEXT, PASSPHRASE)
    with pytest.raises(Exception):
        decrypt_text(encrypted, "wrong_passphrase")

def test_encrypt_decrypt_file(tmp_path):
    original_data = b"Sensitive binary data here."
    file_path = tmp_path / "test_file.txt"

    # Write original file
    with open(file_path, 'wb') as f:
        f.write(original_data)

    # Encrypt file
    encrypt_file(str(file_path), PASSPHRASE)
    encrypted_path = str(file_path) + ".enc"
    assert os.path.exists(encrypted_path)

    # Decrypt file
    decrypt_file(encrypted_path, PASSPHRASE)
    decrypted_path = encrypted_path.replace(".enc", ".dec")
    assert os.path.exists(decrypted_path)

    # Read and compare
    with open(decrypted_path, 'rb') as f:
        decrypted_data = f.read()

    assert decrypted_data == original_data

def test_decrypt_file_with_wrong_passphrase_fails(tmp_path):
    data = b"File contents."
    file_path = tmp_path / "wrong_key_test.txt"

    with open(file_path, 'wb') as f:
        f.write(data)

    encrypt_file(str(file_path), PASSPHRASE)
    encrypted_path = str(file_path) + ".enc"

    # Tamper by using the wrong password
    with pytest.raises(Exception):
        decrypt_file(encrypted_path, "incorrect_passphrase")