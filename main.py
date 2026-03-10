import string
import secrets
import argparse


def generate_password(length=12, use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
    """
    Generate a secure password with guaranteed character diversity.
    """

    char_sets = []
    password = []

    if use_lower:
        char_sets.append(string.ascii_lowercase)
        password.append(secrets.choice(string.ascii_lowercase))

    if use_upper:
        char_sets.append(string.ascii_uppercase)
        password.append(secrets.choice(string.ascii_uppercase))

    if use_digits:
        char_sets.append(string.digits)
        password.append(secrets.choice(string.digits))

    if use_symbols:
        char_sets.append(string.punctuation)
        password.append(secrets.choice(string.punctuation))

    if not char_sets:
        raise ValueError("At least one character set must be enabled.")

    all_chars = "".join(char_sets)

    # Fill remaining length
    while len(password) < length:
        password.append(secrets.choice(all_chars))

    # Shuffle securely
    secrets.SystemRandom().shuffle(password)

    return "".join(password)


def password_strength(length):
    if length < 8:
        return "Weak"
    elif length < 12:
        return "Moderate"
    elif length < 16:
        return "Strong"
    else:
        return "Very Strong"


def main():
    parser = argparse.ArgumentParser(description="Secure Password Generator")

    parser.add_argument("-l", "--length", type=int, default=12, help="Password length")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    parser.add_argument("--no-symbols", action="store_true", help="Exclude special characters")

    args = parser.parse_args()

    password = generate_password(
        length=args.length,
        use_lower=not args.no_lower,
        use_upper=not args.no_upper,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
    )

    print("\nGenerated Password:", password)
    print("Password Strength:", password_strength(args.length))


if __name__ == "__main__":
    main()