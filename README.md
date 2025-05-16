# Threshold Signature

This repository demonstrates a Python implementation of threshold signatures using ECDSA (Elliptic Curve Digital Signature Algorithm) and Shamir's Secret Sharing. The code showcases how a private signing key can be split into multiple shares and later reconstructed, allowing secure distributed signing.

## Example Usage

Run the demo with default settings (5 shares, threshold of 3):

```bash
python main.py
````

You can customize the number of shares and threshold using command-line arguments:

```bash
python main.py -n 6 -t 4
```

### Arguments

* `-n`, `--num-shares`: Number of shares to generate (default: `5`). Must be greater than or equal to the threshold.
* `-t`, `--threshold`: Minimum number of shares required to reconstruct the secret (default: `3`). Must be **at least 1** and **not greater than the number of shares**.

## Features

- **ECDSA Implementation**: Includes scalar multiplication and point operations on elliptic curves (secp256k1, used in Bitcoin).
- **Shamir's Secret Sharing**: Splits a secret (private key) into n shares, requiring only t (threshold) shares to reconstruct it.
- **Threshold Signature Demo**: Shows the full flow from key generation, secret sharing, signing, and signature verification.

## File Overview

- `main.py`: Runs the demo, generates a keypair, splits the private key, reconstructs it, signs a message, and verifies the signature.
- `ecc.py`: Implements elliptic curve cryptography primitives: the `FieldElement` and the `Point` classes.
- `sha256.py`: Includes a self-contained SHA-256 hash function.
- `shamir.py`: Implements Shamir's Secret Sharing, including share generation and secret reconstruction.

## How It Works

1. **Key Generation**: Generates a random ECDSA private key and derives the public key on secp256k1.
2. **Secret Sharing**: Uses Shamir's Secret Sharing to split the private key into multiple shares.
3. **Reconstruction**: Any t (threshold) number of shares can reconstruct the private key.
4. **Signing**: Signs a message with the reconstructed key.
5. **Verification**: Verifies the signature using the public key.
