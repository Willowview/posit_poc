import hashlib
import hmac
import secrets


PASSWORD_HASH_PREFIX = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 600_000


def encode_password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return "$".join(
        (
            PASSWORD_HASH_PREFIX,
            str(PASSWORD_HASH_ITERATIONS),
            salt.hex(),
            digest.hex(),
        )
    )


def verify_password(password, encoded):
    try:
        algorithm, iterations_text, salt_hex, digest_hex = encoded.split("$")
        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (AttributeError, TypeError, ValueError):
        return False

    if (
        algorithm != PASSWORD_HASH_PREFIX
        or iterations < 100_000
        or iterations > 2_000_000
        or len(salt) < 16
        or len(expected) != 32
    ):
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)
