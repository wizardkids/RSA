"""
    Filename: rsa_encryption.py
     Version: 0.1
      Author: Richard E. Rawson
        Date: 2023-04-27
 Description: Use RSA public/private key encryption to encrypt/decrypt text.

PUBLIC KEY CRYPTOGRAPHY IN SUMMARY:
-- A public key is used to encrypt and a separate, different private key to decrypt the message.
-- Each party involved generates a key pair.
-- Each party publishes their public key. This is made widely known to all potential communication partners.
-- Each party secures their private key, which must remain secret.
-- Assuming A desires to send a message to B, A first encrypts the message using B's public key.
-- B can decrypt the message using its private key. Since no one else knows B's private key, this is absolutely secure -- no one else can decrypt it.
Source: https://condor.depaul.edu/ichu/csc415/notes/notes4/rsa.html
"""

import json
import math
from pathlib import Path
from random import randint

import click
from icecream import ic
from pandas import qcut

VERSION = "0.2"


@click.command(help="Encrypt or decrypt [MESSAGE] or [PATH] using RSA encryption. [MESSAGE] must be a quote-delimited string.\n\nThe encrypted content is written to \"encrypted.txt\" and the content of that file is decrypted to \"decrypted.txt\". If either file exists, it will be overwritten.", epilog="EXAMPLE USAGE:\n\nrsa_encryption.py \"The troops roll out at midnight.\" --> encrypts for a specified recipient\n\nrsa_encryption.py --> decrypts \"encrypted.txt\" for a specified recipient")
@click.argument("message", type=str, required=False)
@click.option("-f", "--file", type=click.Path(exists=False), help='File to encrypt.')
@click.option("-p", "--printkeys", is_flag=True, default=False, help="Print the keys for a specified recipient.")
@click.option("-g", "--generate", is_flag=True, default=False, help="Generate keys for sender & recipient.")
@click.version_option(version=VERSION)
def cli(message, file, printkeys, generate) -> None:
    """
    Main entry point for the command-line interface.

    Parameters
    ----------
    message : str -- message to encrypt
    file : Path -- filename containing text to encrypt
    printkeys : str -- flag to print public and private keys
    generate: str -- flag to generate a private key
    """

    # print()
    # ic(message, file, printkeys, generate)
    # print()

    main(message, file, printkeys, generate)


def encrypt_msg(msg) -> None:
    """
    Using the public_key [e, n], encrypt the text in "msg". This function returns a string that will be saved to "encrypted.txt".

    CODENOTE:
        The for... loop was originally:
            e_msg = []
            for s in msg:
                cyphtertext = (ord(s)**e) % n
                e_msg.append(str(cyphtertext))

        This works well for ASCII characters. However, in order to encrypt/decrypt characters with larger code points, we need to convert the string "msg" to bytes and encrypt the message in chunks.

    Parameters
    ----------
    public_key : list[int] -- e, n

    Returns
    -------
    str -- encrypted "msg"... a single string that contains string versions of integers, where each "integer" represents one character in "msg"

    Example
    -------
    "hello" -> 437 730 811 811 1591
    """

    with open("sender.json", 'r', encoding='utf-8') as file:
        sender_keys = json.load(file)
    with open("recipient.json", 'r', encoding='utf-8') as file:
        recipient_keys = json.load(file)

    e: int = recipient_keys['public_key']['e']
    n: int = recipient_keys['public_key']['n']

    chunk_size: int = (n.bit_length() - 1) // 8  # Max bytes that n can handle minus a bit to be safe.
    chunk_size=1 if chunk_size== 0 else chunk_size

    # Encode the message to bytes.
    message_bytes: bytes = msg.encode('utf-8')

    # Convert the bytes to integers for encryption.
    e_msg: list[str] = []
    for i in range(0, len(message_bytes), chunk_size):

        chunk: bytes = message_bytes[i:i + chunk_size]
        chunk_int: int = int.from_bytes(chunk, byteorder='big')

        # The following line computes c = (m**e) mod n behind the scenes.
        # This means decryption needs "m".
        ciphertext = chunk_int**e % n

        e_msg.append(str(ciphertext))

    encrypted_msg: str = " ".join(e_msg)

    # Save the encrypted message.
    with open("encrypted.txt", 'w', encoding="utf-8") as file:
        file.write(encrypted_msg)


def decrypt_msg() -> None:
    """
    Decrypt the contents of "encrypted.txt" using "d" & "n" in "private_key".

    CODENOTE:
        Originally, the for... loop was:
            for cyphertext in encrypt:
                m: int = (cyphtertext**d) % n
                decrypt.append(chr(m))

        This works well for ASCII characters. However, in order to encrypt/decrypt characters with larger code points, we need to decrypt the encrypted message in chunks (and the encryption process had to encrypt bytes in chunks).

    Parameters
    ----------
    private_key : list[int] -- d, n

    Returns
    -------
    str -- decrypted "msg"...
    """

    p = Path("encrypted.txt")
    if p.exists():
        with open(p, "r", encoding='utf-8') as f:
            m: str = f.read()
    else:
        print("\nencrypted.txt does not exist.")
        exit()

    with open("sender.json", 'r', encoding='utf-8') as file:
        sender_keys = json.load(file)
    with open("recipient.json", 'r', encoding='utf-8') as file:
        recipient_keys = json.load(file)

    n: int = recipient_keys['public_key']['n']
    d: int = recipient_keys['private_key']

    decrypted_chunks: list[bytes] = []
    encrypted_chunks: list[int] = [int(x) for x in m.split()]
    for ciphertext in encrypted_chunks:
        decrypted_int = ciphertext**d % n
        decrypted_int: int = pow(ciphertext, d, n)
        chunk_size: int = (decrypted_int.bit_length() + 7) // 8
        decrypted_chunk: bytes = decrypted_int.to_bytes(chunk_size, byteorder='big')
        decrypted_chunks.append(decrypted_chunk)

    # Join the decrypted byte chunks
    try:
        decrypted_bytes: bytes = b''.join(decrypted_chunks)
        decrypted_msg: str = decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError:
        print("Access denied. Cannot decrypt with the provided key.")
        exit()

    with open('decrypted.txt', 'w', encoding='utf-8') as file:
        file.write(decrypted_msg)


def generate_keys():
    """
    This function generates the integers needed to construct the public and private keys, namely:
            p, q: Two random integers, the bigger the better, both primes
            n: p * q -- part of the public key
            T: (p-1) * (q-1)
            e: coprime of T; part of the public_key
            d: the modular inverse of e and T; this is the private_key
            m: a secret number

            sender sends c and his public key (e & n):
            c = m**e % n

            recipient calculates m using his public key (e & n)
            d*e = 1 % T
            m = c**d % n

    EXAMPLE:

    SENDER
        p = 5  q = 11
        n = p*q = 55 (public)
        T = (p-1)(q-1) = 40
        e = 3 (public) any coprime of T will work here
        m = 7
        c = m**e % n = 7**3 % 55 = 13 --> sent to recipient

    RECIPIENT:
        receives c, n, and e
        d * e = 1 % T --> d * 3 = 1 % 40 --> d = 27 (modular inverse of e,T or 3,40)
        m = c**d % n = 13**27 mod 55 = 7


    CODENOTE:
        Integer values here are kept purposely small because there is no need rock-solid encryption, and using large numbers slows the processes of encrypt/decryption significantly.
    """

    # round 1 creates the sender's keys and round 2 creates the recipient's keys.
    for round in range(1, 3):

        # STEP 1:
        #       SELECT TWO PRIME NUMBERS AND p < q
        #       CREATE semi-prime "n" AS THE PRODUCT OF p * q
        #       CREATE "T" AS THE TOTIENT
        n = 100
        # we are purposely keeping "n" below 1000
        while n <= 1000:
            p = 4
            while not is_prime(p):
                p: int = randint(5, 100)
            q = 4
            while not is_prime(q):
                q: int = randint(4, p - 1)
            n: int = p * q
        p, q = sorted([p, q])
        T: int = (p - 1) * (q - 1)   # T is for Totient

        # STEP 2: CREATE "e", THE PUBLIC KEY
        #       "e" MUST BE A PRIME
        #       "e" < "T"
        #       "e" MUST NOT BE A FACTOR OF "T"
        for e in range(max(p, q) + 1, T-1):

            # "e" is not a  factor of "T" is T % e != 0
            f = T % e

            if is_prime(e) and e < T and f != 0:
                break

        # STEP 3: CREATE A PRIVATE KEY "d" such that (d*e) % T == 1
        #       this requires using a multiplicative inverse function
        d: int = modinv(e, T)

        # c: int = (m**e) % n

        keys = {"public_key": {"n": n, "e": e, "T": T}, "private_key": d, "p": p, "q": q}
        filename = "sender.json" if round == 1 else "recipient.json"
        with open(filename, 'w', encoding='utf-8') as file:
                json.dump(keys, file)


# ==== UTILITY FUNCTIONS =====================================================
def modinv(a: int, b: int) -> int:
    """
    A multiplicative inverse is two numbers that multiply together to yield (1 mod m).
    This function returns the modular inverse, or multiplicative inverse, of (a mod b).
    Requirements: a < b and gcd(a, b) = 1

    Parameters
    ----------
    a : int -- any integer
    b : int -- any integer larger than b

    Returns
    -------
    int -- the modular inverse of "a mod b"

    Examples
    --------
    test_cases = [
         (3, 11) ->  4, therefore   3 *  4 % 11 == 1
        (10, 17) -> 12, therefore  10 * 12 % 17 == 1
          (2, 5) ->  3, therefore   2 *  3 %  5 == 1
         (7, 13) ->  2, therefore   7 *  2 % 13 == 1
         (8, 29) -> 11, therefore   8 * 11 % 29 == 1
        ]
    """

    saved: int = b
    x, y, u, v = 0, 1, 1, 0
    while a:
        q: int = b // a
        r: int = b % a
        m: int = x - u * q
        n: int = y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return x % saved


def coprime(a: int, b: int) -> bool:
    """
    Returns True if "gcd(a, b) == 1", i.e. if "a" and "b" are coprime.Two numbers are coprime if their GCD is 1 and they share no common factors other than 1.

    Parameters
    ----------
    a : int -- first integer
    b : int -- second integer

    Returns
    -------
    bool -- True if a and b are coprime

    Examples
    --------
    8 and 9 are coprime because their only common factor is 1. However, 6 and 9 are not coprime because they share the common factor 3.
    """
    return math.gcd(a, b) == 1


def is_prime(n: int) -> bool:
    """
    Returns True if "n" is a prime number. A prime number is a positive integer greater than 1 that has no positive integer divisors other than 1 and itself.

    Parameters
    ----------
    n : int -- any integer

    Returns
    -------
    bool -- True if "n" is a prime number.
    """
    if n <= 1:
        return False

    for i in range(2, n):
        if n % i == 0:
            return False

    return True
def print_ints(p, q, public_key, private_key) -> None:
    """
    Used only for debugging purposes. Prints p, q, n, T, e, d, public_key, and private_key
    """
    print()
    print(
        f'            p: {p}\n            q: {q}\n      n (p*q): {p * q}\nT (p-1)*(q-1): {(p - 1) * (q - 1)}\n            e: {public_key[0]}\n            d: {private_key[0]}', sep='')
    print(f' Public key [e, n]: {public_key}')
    print(f'Private key [d, n]: {private_key}')
    print()


def print_keys() -> None:
    """
    Print the public and private keys for a recipient.
    """
    recipient: str = input("Keys for which recipient: ").lower()
    keys = get_keys(recipient)

    print(f' Public key: {keys["public_key"]}')
    print(f'Private key: {keys["private_key"]}')

    # These two variables are included in the json file, but are only used
    # for debugging, so I'm not printing them here.
    # print(f'          p: {keys["p"]}')
    # print(f'          q: {keys["q"]}')


def get_keys(recipient: str) -> dict:
    """
    Retrieve the keys for the provided recipient from that recipient's .json file.

    Parameters
    ----------
    recipient : str -- name of the user (recipient)

    Returns
    -------
    dict -- dictioary containing public and private keys
    """
    filename: str = recipient.strip() + ".json"
    try:
        with open(filename, 'r', encoding="utf-8") as f:
            keys = json.load(f)
    except FileNotFoundError:
        print(f'\nKeys for "{recipient}" do not exist.')
        print("Generate keys using --generate option.")
        exit()

    return keys


# ==== END UTILITY FUNCTIONS =================================================

def main(msg: str, file: str, printkeys: str, generate: str) -> None:
    """
    Organizing function for this CLI. If a "msg" or a "file" is included, then encrypt the text. If no arguments are provided, then decrypt the contents of "encrypted.txt".

    Parameters
    ----------
    message : str -- message to encrypt
    file : Path -- filename containing text to encrypt
    printkeys : str -- flag to print public and private keys
    generate: str -- flag to generate a private key
    """

    # generate_keys() takes no arguments but creates a public_key [e, n], p, q, and private_key [d, n], then saves them in a json file.
    # p and q are only required for debugging (see print_ints() to print the details)
    # ! This option is used to generate keys for a sender and a recipient
    if generate:
        generate_keys()
        exit()

    if printkeys:
        print_keys()
        exit()

    # Make sure we can find the file and put its contents into "message".
    if file:
        p = Path(file)
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                message: str = f.read()
        else:
            print(f'Could not find file "{file}"')
            exit()
    elif msg:
        message = msg
    else:
        message = msg

    # If there's a message, encrypt it, otherwise assume we want to decrypt "encrypted.txt"
    if message:
        # recipient: str = input("Who will receive this message/file: ").lower()
        # keys = get_keys(recipient)
        # encrypted_msg: str = encrypt_msg(message, keys['public_key'])

        # with open('encrypted.txt', 'w', encoding="utf-8") as f:
        #     f.write(encrypted_msg)
        encrypt_msg(message)
        print('Encrypted message saved as "encrypted.txt".')

    else:
        # recipient: str = input("Who is the recipient of this message/file: ").lower()
        # keys = get_keys(recipient)
        # decrypted_msg: str = decrypt_msg(keys['private_key'])
        # with open('decrypted.txt', 'w', encoding='utf-8') as f:
        #     f.write(decrypted_msg)
        decrypt_msg()
        print('Decrypted message saved as "decrypted.txt"')


if __name__ == '__main__':

    # The following strings comprise a variety of test messages.

    # Plain text with two CRLF characters.
    msg1 = "Who is God? What do you imagine this Divine Being is like? God is likely shaped by a variety of factors, including what you were taught in your faith community, the way clergy modeled themselves, your relationship with parents, or significant life events. These can intersect with each other.\n\nFor example, you might have learned to view God as a father based on Scriptures that use this metaphor. For example, you might have learned to view God as a father based on Scriptures that use this metaphor."

    # Plain text with some very common unicode characters.
    msg2 = "Paul asks prayer that God might “open a door” so that he can proclaim “the mystery of Christ” (4:3). The “kingdom of God” (4:11) can also be called “the kingdom of the Son he loves” (1:13). The cumulative effect of these references, when set beside the explicit assertions in 1:15, 1:19, and 2:9, is to suggest that Christ is divine: he is himself God. Colossians is therefore a prime witness to the “christological monotheism” that characterizes early Christianity."

    # Plain text with both common and uncommon unicode characters.
    msg3 = "In the café, the bánh mì sandwich is a popular choice among the regulars. The flaky baguette, stuffed with savory grilled pork, pickled daikon and carrots, fresh cilantro, and a dollop of sriracha mayo, is the perfect lunchtime indulgence. As I sipped my matcha latte, I noticed the barista's shirt had a cute ねこ (neko, or cat) graphic on it. It reminded me of the time I visited Tokyo and saw the famous 東京タワー (Tokyo Tower) at night, aglow with colorful lights. The world is full of unique and beautiful symbols, and Unicode makes it possible to express them all in one cohesive language."

    print()
    cli()
