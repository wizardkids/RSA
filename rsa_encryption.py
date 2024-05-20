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
import sys
from pathlib import Path
from random import randint

from rich import print
from rich.traceback import install

install(show_locals=True)

import click
from icecream import ic

VERSION = "0.1"

@click.command(help="Encrypt or decrypt a message using RSA encryption. [SOURCE] can be either a quote-delimited string or a file.\n\nThe encrypted message is written to \"encrypted.txt\" and the content of that file is decrypted to \"decrypted.txt\". If either file exists, it will be overwritten.")
@click.option("-s", "source", type=str, required=False, help="Message to encrypt.")
@click.option("-e", "--encrypt", is_flag=True, help="Encrypt a message using RSA public key encryption.")
@click.option("-d", "--decrypt", is_flag=True, help="Decrypt a message using RSA private key decryption.")
@click.version_option(version=VERSION)
def cli(source, encrypt, decrypt) -> None:
    ic(source)
    ic(encrypt)
    ic(decrypt)

    main(source, encrypt, decrypt)

def modinv(a: int, b: int) -> int:
    """
    Returns the modular inverse of a mod b.
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


def generate_keys() -> tuple[list[int], int, int, list[int]]:
    """
    There are two sub-functions in this function. One [get_ints()] generates the integers needed to construct the keys and the other [generate_public_private()] generates the keys themselves.

    p and q are returned only for debugging purposes. They are required to create the keys, but not to use the keys.

    Returns
    -------
    tuple[list[int], int, int, list[int]] -- public_key, p, q, private_key
        public_key [list]: [e, n]
        p (int): used to create n and T
        q (int): used to create n and T
        private_key [list]: [d, n]
    """

    def generate_public_private() -> tuple[list[int], list[int], int, int]:
        """
        This function generates p, q, n, d, and e. p and q are returned only for debugging purposes. They are required to create the keys, but not to use the keys.

        Returns
        -------
        tuple[list[int], list[int], int, int] -- public_key, private_key, p, q
            public_key = [e, n]
            private_key = [d, n]
            p, q for debugging purposes only
        """

        p, q, e, d, n = get_ints()

        # CODENOTE: We could return T, rather than p,q since generate_private() only needs T and not p,q. However, for the time being, we pass p, q for debugging purposes, so that we can print p,q after running all the functions herein.

        # Here, we return the public_key, private_key, p, and q:
        return [e, n], [d, n], p, q

    def get_ints() -> tuple[int, int, int, int, int]:
        """
        This function generates the integers needed to construct the public and private keys, namely:
                p, q: Two random integers, the bigger the better, both primes
                n: p * q
                T: (p-1) * (q-1)
                e: prime number, where e and T are coprime; this is the public_key
                d: the modular inverse of e and T; this is the private_key

        Integer values are kept purposely small because there is no need rock-solid encryption, and using large numbers slows the processes of encrypt/decryption significantly.

        Returns
        -------
        tuple[int, int, int, int, int] -- p, q, e, d, n
        """

        n = 100
        while n <= 1000:
            p = 4
            while not is_prime(p):
                p = randint(5, 100)
            q = 4
            while not is_prime(q):
                q = randint(4, p - 1)
            n = p * q

        p, q = sorted([p, q])
        T: int = (p - 1) * (q - 1)   # T is for Totient

        e, d = randint(5, 23), 3
        while d <= e:
            # e must be prime, < T, and must not be a factor of T
            for e in range(max(p, q) + 1, T):
                """
                -- (d * e) mod T == 1  and solve for d... requires a modular inverse.
                -- In other words, the mod T of the private_key * public_key is 1.
                -- If T = 108, e = 29 then d = 41 satisfies this requirement...
                -- (41 * 29) % 108 = 1. BUT, to find "d" we need a modular inverse function.
                """
                d: int = modinv(e, T)    # modular inverse of e mod T

                if is_prime(e) and coprime(e, T):
                    break

        return p, q, e, d, n

    public_key, private_key, p, q = generate_public_private()

    return public_key, p, q, private_key


def encrypt_msg(msg, public_key) -> str:
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

    e: int = public_key[0]
    n: int = public_key[1]

    chunk_size: int = (n.bit_length() - 1) // 8  # Max bytes that n can handle minus a bit to be safe

    # Encode the message to bytes
    message_bytes = msg.encode('utf-8')

    # Convert the bytes to integers for encryption
    e_msg: list[int] = []
    for i in range(0, len(message_bytes), chunk_size):
        chunk = message_bytes[i:i + chunk_size]
        chunk_int: int = int.from_bytes(chunk, byteorder='big')
        ciphertext: int = pow(chunk_int, e, n)
        e_msg.append(str(ciphertext))

    encrypted_msg: str = " ".join(e_msg)

    return encrypted_msg


def decrypt_msg(private_key) -> str:
    """
    Decrypt the contents of "encrypted.txt" using d, n in private_key.

    CODENOTE:
        Originally, the for... loop was:
            for cyphertext in encrypt:
                m: int = (cyphtertext**d) % n
                decrypt.append(chr(m))

        This works well for ASCII characters. However, in order to encrypt/decrypt characters with larger code points, we need to decrypt the encrypted message in chunks.

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
            msg = f.read()
    else:
        print("\nencrypted.txt does not exist.")
        exit()

    d: int = private_key[0]
    n: int = private_key[1]

    decrypted_chunks: list[bytes] = []
    encrypted_chunks: list[int] = [int(x) for x in msg.split()]
    for ciphertext in encrypted_chunks:
        decrypted_int = pow(ciphertext, d, n)
        chunk_size = (decrypted_int.bit_length() + 7) // 8
        decrypted_chunk = decrypted_int.to_bytes(chunk_size, byteorder='big')
        decrypted_chunks.append(decrypted_chunk)

    # Join the decrypted byte chunks
    decrypted_bytes = b''.join(decrypted_chunks)
    decrypted_msg: str = decrypted_bytes.decode('utf-8')

    return decrypted_msg


def print_ints(p, q, public_key, private_key) -> None:
    """
    Used only for debugging purposes. Prints p, q, n, T, e, d, public_key and private_key
    """
    print()
    print(
        f'            p: {p}\n            q: {q}\n      n (p*q): {p * q}\nT (p-1)*(q-1): {(p - 1) * (q - 1)}\n            e: {public_key[0]}\n            d: {private_key[0]}', sep='')
    print(f' Public key [e, n]: {public_key}')
    print(f'Private key [d, n]: {private_key}')
    print()


def main(source: str, encrypt: str, decrypt: str) -> None:
    """
    read() reads in the file and returns ONE string comprising all the lines in the file where each line ends with \\n
    """

    # Determine if "message" is a filename or not. A TypeError can occur if Path(source) raises an exception.
    try:
        p = Path(source)
        if p.exists():
            with open(p, 'r') as f:
                msg = f.read()
        else:
            msg: str = source
    except TypeError:
        msg: str = source

    # generate_keys() takes no arguments but returns public_key [e, n], p, q, and private_key [d, n]
    # p and q are only required for debugging (see print_ints() to print the details)
    public_key, p, q, private_key = generate_keys()

    if encrypt:
        encrypted_msg: str = encrypt_msg(msg, public_key)

        # To decrypt, we need the private key, so save it in a file.
        with open("private_key.txt", 'w') as f:
            json.dump(private_key, f)

        with open('encrypted.txt', 'w', encoding="utf-8") as f:
            f.write(encrypted_msg)

        print(f'\nEncrypted message saved as "encrypted.txt".')

    elif decrypt:
        # To decrypt, get the private key from file.
        with open("private_key.txt", 'r') as f:
            private_key: list[int]= json.load(f)

        decrypted_msg: str = decrypt_msg(private_key)
        with open('decrypted.txt', 'w', encoding='utf-8') as f:
            f.write(decrypted_msg)

        print(f'\nDecrypted message saved as "decrypted.txt"')

    else:
        print('No action specified. Please specify either "--encrypt" or "--decrypt".')


if __name__ == '__main__':

    # The following strings comprise a variety of test messages.

    # Plain text with two CRLF characters.
    msg1 = "Who is God? What do you imagine this Divine Being is like? God is likely shaped by a variety of factors, including what you were taught in your faith community, the way clergy modeled themselves, your relationship with parents, or significant life events. These can intersect with each other.\n\nFor example, you might have learned to view God as a father based on Scriptures that use this metaphor. For example, you might have learned to view God as a father based on Scriptures that use this metaphor."

    # Plain text with some very common unicode characters.
    msg2 = "Paul asks prayer that God might “open a door” so that he can proclaim “the mystery of Christ” (4:3). The “kingdom of God” (4:11) can also be called “the kingdom of the Son he loves” (1:13). The cumulative effect of these references, when set beside the explicit assertions in 1:15, 1:19, and 2:9, is to suggest that Christ is divine: he is himself God. Colossians is therefore a prime witness to the “christological monotheism” that characterizes early Christianity.73"

    # Plain text with both common and uncommon unicode characters.
    msg3 = "In the café, the bánh mì sandwich is a popular choice among the regulars. The flaky baguette, stuffed with savory grilled pork, pickled daikon and carrots, fresh cilantro, and a dollop of sriracha mayo, is the perfect lunchtime indulgence. As I sipped my matcha latte, I noticed the barista's shirt had a cute ねこ (neko, or cat) graphic on it. It reminded me of the time I visited Tokyo and saw the famous 東京タワー (Tokyo Tower) at night, aglow with colorful lights. The world is full of unique and beautiful symbols, and Unicode makes it possible to express them all in one cohesive language."

    msg = msg3
    filename = 'abair blog.txt'
    # args: main(msg, filename)
    # main("", "")

    cli()
