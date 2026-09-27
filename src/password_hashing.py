from __future__ import annotations

import bcrypt


def hash_password(password: str, rounds: int = 12) -> str:
    if not password:
        raise ValueError("Password must not be empty")

    salt = bcrypt.gensalt(rounds=rounds)
    password_hash = bcrypt.hashpw(password.encode("utf-8"), salt)
    return password_hash.decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(
        password.encode("utf-8"),
        stored_hash.encode("utf-8"),
    )


if __name__ == "__main__":
    password = "Example-Lab-Password"
    stored_hash = hash_password(password)

    print("bcrypt password hashing demonstration")
    print("Hash:", stored_hash)
    print("Correct password:", verify_password(password, stored_hash))
    print("Wrong password:", verify_password("wrong-password", stored_hash))
