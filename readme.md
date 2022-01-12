# QR Secrets

QR secrets is a cryptographically secure mechanism to store secret data with the highest levels of security. Incorporating; AES256-GCM-HKDF-ARGON2 and ECIES-AES256-GCM-HKDF-SHA256. Rated for a 256 bit security level and requiring two keys, one private Elliptic Curve key and one passphrase known as the Master Key. You only require the master key to encrypt and the public key of Elliptic key. This allows you to, if needed, encrypt on one machine and only decrypt your hardened secure environment, protecting your other stored secrets from being viewed if one key were to be compromised.

The whole point of this project is to store secrets in encrypted QR codes. This project allows you to securely generate QR codes for sensitive data such as;

- Cryptocurrency Seeds
- Password manager master passwords
- TOTP secrets
- Banking information
- Paper key backups
- Login credentials
- Secure notes
- Or anything you want to keep safe & private

QR secrets allows you to not only export to QR codes but also to files to be stored on Disk or Tape.

# Security Guarantees

1. 256 bit security using [AES256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) + Symmetric key + Salt locked behind [PKI](https://en.wikipedia.org/wiki/Public-key_cryptography) with a 521bit Elliptic curve (256 bit security key)
2. Computationally impossible to brute force.
3. Quantum resistance, no known quantum attacks brings 256bit security low enough into a realm where it could be cracked.
4. Even if one key was to be compromised the data would still be secure.
5. Different keys for each "file" encrypted.
6. Hide true plaintext length with padding.
7. Configuration data hidden.
8. Tamper proof, if any bit was to be modified (other than version num & the magic number) the data would not be able to decrypt ([AHEAD Cipher](https://en.wikipedia.org/wiki/Authenticated_encryption)).

# Cryptography & Format Breakdown

The data is stored in a byte format, with 3 distinct sections within whats called a Container.

1. The MetaData section holds the version of the protocol/format, the curve ID and the hash ID which are both used for decrypting the Encrypted Parameters section. And of course it starts with a 16bit magic number to detect the file format of QRsecrets

2. The Encrypted Parameters section. This holds the salt/nonce which is used in the Argon2 KDF. This section also holds the Argon2 parameters and padding size. This section is encrypted using ECIES to the public key.

3. The CipherText section is self explanatory it is the section which holds the encrypted data + padding. It uses AES256-GCM-HKDF-ARGON2 with the Master key and the Salt from the Encrypted Parameters section. You can only decrypt this section if you have decrypted the one above.

# Curves

QR secrets supports the following curves:

- nist-p224
- nist-p256
- nist-p384
- nist-p521

# Cryptographic Hash Functions

For the Metadata section the following hash functions are available. All of these functions are ran through HKDF to derive a encryption key.

- SHA256
- SHA512
- SHA3-256
- SHA3-512

# KDFs

QRsecrets doesn't allow the modification of the KDF on the Ciphertext section, but rather allows the KDF parameters to be modified. Using Argon2 and HKDF the key is derived.

# Package

This repo is both a command line tool and a package you can include into your Go applications.
