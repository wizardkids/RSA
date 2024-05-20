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

import math
import sys
from random import randint

# ==============================================================================


# ==============================================================================


def modinv(a, b):
    """
    Returns the modular inverse of a mod b.
    Pre: a < b and gcd(a, b) = 1
    """
    saved = b
    x, y, u, v = 0, 1, 1, 0
    while a:
        q, r = b // a, b % a
        m, n = x - u*q, y - v*q
        b, a, x, y, u, v = a, r, u, v, m, n
    return x % saved


def coprime(a, b):
    """
    Returns True if "gcd(a, b) == 1", i.e. if "a" and "b" are coprime
    """
    return math.gcd(a, b) == 1


def is_prime(n):
    """
    Returns True if n is a prime number.
    """
    if n <= 1:
        return False
    for i in range(2, n):
        if n % i == 0:
            return False
    return True


def generate_keys():
    """
    There are two sub-functions in this function. One [get_ints()] generates the integers needed to construct the keys and the other [generate_public_private()] generates the keys themselves.

    Returns:
        public_key [list]: [e, n]
        p (int): used to create n and T
        q (int): used to create n and T
        private_key [list]: [d, n]

    p and q are returned only for debugging purposes. They are required to create the keys, but not to use the keys.
    """

    def generate_public_private():
        """
        This function generates p, q, n, d, and e.

        Returns:
            public_key = [e, n]
            private_key = [d, n]
            p, q for debugging purposes only
        """

        p, q, e, d, n = get_ints()

        # CODENOTE: We could return T, rather than p,q since generate_private() only needs T and not p,q. However, for the time being, we pass p, q for debugging purposes, so that we can print p,q after running all the functions herein.

        # Here, we return the public_key, private_key, p, and q to main():

        return [e, n], [d, n], p, q

    def get_ints():
        """
        This function generates the integers needed to construct the public and private keys, namely:
        p, q: Two random integers, the bigger the better, both primes
        n: p * q
        T: (p-1) * (q-1)
        e: prime number, where e and T are coprime; this is the public_key
        d: the modular inverse of e and T; this is the private_key

        Integer values are kept purposely small because there is no need rock-solid encryption, and using large numbers slows the processes of encrypt/decryption significantly.

        Returns:
            p, q, e, d, n
        """

        n = 100
        while n <= 1000:
            p = 4
            while not is_prime(p):
                p = randint(5, 100)
            q = 4
            while not is_prime(q):
                q = randint(4, p-1)
            n = p * q

        p, q = sorted([p, q])
        T = (p - 1) * (q - 1)   # T is for Totient

        e, d = randint(5, 23), 3
        while d <= e:
            # e must be prime, < T, and must not be a factor of T
            for e in range(max(p, q)+1, T):
                """
                -- (d * e) mod T == 1  and solve for d... requires a modular inverse.
                -- In other words, the mod T of the private_key * public_key is 1.
                -- If T = 108, e = 29 then d = 41 satisfies this requirement...
                -- (41 * 29) % 108 = 1. BUT, to find "d" we need a modular inverse function.
                """
                d = modinv(e, T)    # modular inverse of e mod T

                if is_prime(e) and coprime(e, T):
                    break

        return p, q, e, d, n


    public_key, private_key, p, q = generate_public_private()

    return public_key, p, q, private_key


def encrypt(msg, public_key):
    """
    Using the public_key [e, n], encrypt the text in "msg".

    Args:
        msg (str): the text to decrypt
        public_key [list]: e, n

    Returns:
        str: the encrypted test: a single string that contains string versions of integers, where each "integer" represents one character in "msg"
    """
    e = public_key[0]
    n = public_key[1]

    msg_bytes = [bytes([b]) for b in msg]
    msg_ints = []
    for b in msg_bytes:
        msg_ints.append(int.from_bytes(b, 'big'))

    e_msg = []
    for i in msg_ints:
        cyphertext = (i**e) % n
        e_msg.append(str(cyphertext))

    encrypted_msg = " ".join(e_msg)

    return encrypted_msg

def int2bytes(number: int, fill_size: int = 0) -> bytes:
    """
    Convert an unsigned integer to bytes (big-endian)::
    Does not preserve leading zeros if you don't specify a fill size.
    :param number:
        Integer value
    :param fill_size:
        If the optional fill size is given the length of the resulting
        byte string is expected to be the fill size and will be padded
        with prefix zero bytes to satisfy that length.
    :returns:
        Raw bytes (base-256 representation).
    :raises:
        ``OverflowError`` when fill_size is given and the number takes up more
        bytes than fit into the block. This requires the ``overflow``
        argument to this function to be set to ``False`` otherwise, no
        error will be raised.

    ============================================================================
    ! This function comes, unaltered, "python-rsa/rsa/transform.py" on github
    ! https://github.com/sybrenstuvel/python-rsa/blob/main/rsa/transform.py
    ============================================================================
    """

    if number < 0:
        raise ValueError("Number must be an unsigned integer: %d" % number)

    bytes_required = max(1, math.ceil(number.bit_length() / 8))

    if fill_size > 0:
        return number.to_bytes(fill_size, "big")

    return number.to_bytes(bytes_required, "big")


def decrypt(msg, private_key):
    """
    Decrypt "msg" using d, n in private_key.

    Args:
        msg (str): see encrypt() for description
        private_key (list): d, n

    Returns:
        str: the decrypted text, as a single string
    """
    d = private_key[0]
    n = private_key[1]

    msg_back = []
    encrypt = [int(x) for x in msg.split()]
    for ciphertext in encrypt:
        m = (ciphertext**d) % n
        msg_back.append(int2bytes(m))

    decrypted_msg = b"".join(msg_back)

    return decrypted_msg


def print_ints(p, q, public_key, private_key):
    """
    Used only for debugging purposes. Prints p, q, n, T, e, d, public_key and private_key
    """
    print()
    print(
        f'            p: {p}\n            q: {q}\n      n (p*q): {p*q}\nT (p-1)*(q-1): {(p-1)*(q-1)}\n            e: {public_key[0]}\n            d: {private_key[0]}', sep='')
    print(f' Public key [e, n]: {public_key}')
    print(f'Private key [d, n]: {private_key}')
    print()

def cli():
    # If there are three arguments (first one is the script name), then
    # the first is set to an empty string and the second is taken as a file name.
    if len(sys.argv) == 3:
        msg = ""
        filename = sys.argv[2]
    elif len(sys.argv) == 2:
        msg = sys.argv[1]
        filename = ''
    else:
        msg, filename = '', ''

    return msg, filename


def main(msg, filename):
    if len(sys.argv) > 1:
        msg, filename = cli()
    else:
        print('\nCOMMAND LINE ARGUMENTS (choose one or the other):\n   1. message (in quotes)\n   2. filename.ext\n\nInclude a message to handle just the text.\nInclude an empty string "" and a filename to handle a file.\n\nNOTE 1: Put file names with spaces in quotes.\nNOTE 2: Including only a file name will submit that name as just text.')

    if not msg and not filename:
        print("\nNo message or file to process.\n")
        sys.exit()

    # [e, n] and [d, n]
    # p and q only required for debugging (see print_ints)
    public_key, p, q, private_key = generate_keys()

    if not msg:
        with open(filename, 'rb') as f:
            msg = f.read()

    encrypted_msg = encrypt(msg, public_key)
    with open('encrypted_file.bin', 'w') as f:
        f.write(encrypted_msg)


    decrypted_msg = decrypt(encrypted_msg, private_key)
    with open('decrypted_file.png', 'wb') as f:
        f.write(decrypted_msg)

    print(f'\nEncrypted file saved as "encrypted_file.bin"\nDecrypted message saved as "decrypted_file.png"')

    # print()
    # print(msg)
    # print()
    # print(encrypted_msg)
    # print()
    # print(decrypted_msg)

    # print_ints(p, q, public_key, private_key)


if __name__ == '__main__':

    # The following strings comprise a variety of test messages.

    # Plain text with two CRLF characters.
    msg1 = "Who is God? What do you imagine this Divine Being is like? God is likely shaped by a variety of factors, including what you were taught in your faith community, the way clergy modeled themselves, your relationship with parents, or significant life events. These can intersect with each other.\n\nFor example, you might have learned to view God as a father based on Scriptures that use this metaphor. For example, you might have learned to view God as a father based on Scriptures that use this metaphor."

    # Plain text with some very common unicode characters.
    msg2 = "Paul asks prayer that God might “open a door” so that he can proclaim “the mystery of Christ” (4:3). The “kingdom of God” (4:11) can also be called “the kingdom of the Son he loves” (1:13). The cumulative effect of these references, when set beside the explicit assertions in 1:15, 1:19, and 2:9, is to suggest that Christ is divine: he is himself God. Colossians is therefore a prime witness to the “christological monotheism” that characterizes early Christianity.73"

    # Plain text with both common and uncommon unicode characters.
    msg3 = "In the café, the bánh mì sandwich is a popular choice among the regulars. The flaky baguette, stuffed with savory grilled pork, pickled daikon and carrots, fresh cilantro, and a dollop of sriracha mayo, is the perfect lunchtime indulgence. As I sipped my matcha latte, I noticed the barista's shirt had a cute ねこ (neko, or cat) graphic on it. It reminded me of the time I visited Tokyo and saw the famous 東京タワー (Tokyo Tower) at night, aglow with colorful lights. The world is full of unique and beautiful symbols, and Unicode makes it possible to express them all in one cohesive language."

    msg = msg3
    filename = 'weather.png'
    # args: main(msg, filename)
    main("", filename)
