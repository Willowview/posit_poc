import getpass

from password_hash import encode_password_hash


def main():
    password = getpass.getpass("Editor password (minimum 12 characters): ")
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")
    confirmation = getpass.getpass("Confirm editor password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    print(encode_password_hash(password))


if __name__ == "__main__":
    main()
