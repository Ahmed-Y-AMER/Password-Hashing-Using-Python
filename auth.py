import hashlib
import hmac
import os
import secrets

FILE_NAME = "users.txt"


def hash_password(password, salt):
    combined = password + salt
    return hashlib.sha256(combined.encode()).hexdigest()


def register(username, password, filename=FILE_NAME):
    if not username or "|" in username or "\n" in username or not password:
        print("Invalid username or password.")
        return False

    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                if line.split("|", 1)[0] == username:
                    print("Username already exists.")
                    return False

    salt = secrets.token_hex(16)
    hashed_password = hash_password(password, salt)

    with open(filename, "a", encoding="utf-8") as file:
        file.write(f"{username}|{salt}|{hashed_password}\n")

    print("Registration successful.")
    return True


def login(username, password, filename=FILE_NAME):
    if not os.path.exists(filename):
        print("User not found.")
        return False

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            saved_username, salt, saved_hash = line.strip().split("|", 2)

            if saved_username == username:
                current_hash = hash_password(password, salt)

                if hmac.compare_digest(current_hash, saved_hash):
                    print("Login successful.")
                    return True

                print("Wrong password.")
                return False

    print("User not found.")
    return False


def main():
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Choose: ")

        if choice == "1":
            username = input("Username: ").strip()
            password = input("Password: ")
            register(username, password)

        elif choice == "2":
            username = input("Username: ").strip()
            password = input("Password: ")
            login(username, password)

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
