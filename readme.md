# RSA Encryption/Decryption

This Python script implements the RSA (Rivest-Shamir-Adleman) encryption algorithm, which is a widely used public-key cryptography system. It allows you to encrypt and decrypt messages using a pair of public and private keys.

## Description

The RSA algorithm is based on the practical difficulty of factoring the product of two large prime numbers. It works by generating a public key and a private key, which are mathematically linked. The public key can be shared with anyone who wants to encrypt a message for you, while the private key is kept secret and used for decryption.

### Public key cryptography in summary:
- A public key is used to encrypt and a separate, different private key to decrypt the message.
- The recipient party generates a key pair and publishes their public key (*i.e.*, sends their public key to the person who needs to encrypt documents that will be sent to the recipient).
- Private keys are secured and must remain secret.
- Assuming A desires to send a message to B, A first encrypts the message using B's public key.
- B can decrypt the message using its private key. Since no one else knows B's private key, this is absolutely secure -- no one else can decrypt it.

### Generation of public/private keys:
The generate_keys() function generates the integers needed to construct public and private keys, namely:

- `p`, `q`: Two random integers, the bigger the better, both primes
- `n`: `p * q` -- part of the public key
- `T`: (`p`-1) * (`q`-1) -->  (`T` stands for totient)
- `e`: coprime of `T`; part of the public_key
- `d`: the modular inverse of `e` and `T`; this is the private_key

**To encrypt a message:** the sender calculates `m**e % n` where `m` is the message, and `e` and `n` are the sender's public key

**To decrypt the ciphertext:** the recipient calculates `c**d % n`, where `c` is the ciphertext, and `d` and `n` are the recipient's public and private keys.

## Usage
```
Usage: rsa_encryption.py [OPTIONS] [MESSAGE]

  Prepare an encrypted [MESSAGE] or [PATH] using RSA encryption for
  a specified recipient using the recipient's public key. The
  content of that file is decrypted by the recipient using their
  private key. [MESSAGE] must be a quote-delimited string.

Options:
  -f, --file PATH  File to encrypt.
  -p, --printkeys  Print the keys for a specified
                   recipient.
  -g, --generate   Generate keys for a specified
                   keyholder.
  --version        Show the version and exit.
  --help           Show this message and exit.

  Encrypted content is saved in "encrypted.txt" while decrypted
  content is saved to "decrypted.txt". If either .txt file exists,
  it will be overwritten.
```
### Example usage:

**Encrypt a message:**
`rsa_encryption.py "The troops roll out at
  midnight."` --> encrypts for a specified recipient

This will encrypt the message for a specified recipient using their public key and save the encrypted message to `encrypted.txt`.

**Decrypt an encrypted message:**

`rsa_encryption.py` --> decrypts "encrypted.txt" for

This will decrypt the contents of `encrypted.txt` using the recipient's private key and save the decrypted message to `decrypted.txt`.

**Generate keys for a recipient:**

`rsa_encryption.py --generate`

This will generate a public and private key pair for a specified recipient and save them in a JSON file with the recipient's name.

**Print keys for a recipient:**

`rsa_encryption.py --printkeys`

This will print the public and private keys for a specified recipient.

## Notes
- The private key must be kept secret and secure.
- The script uses relatively small prime numbers *for demonstration purposes*, which will not provide strong encryption in real-world scenarios. Of course, storing keys in the same location as the encrypted message is a serious violation of Asimov's three laws of cybersecurity: (1) Don't (2) ever (3) do that.

## Dependencies
- [click](https://click.palletsprojects.com/en/8.1.x/) (for command-line interface)