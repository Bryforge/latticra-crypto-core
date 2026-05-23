# Latticra Crypto Core

Latticra Crypto Core is an experimental cryptographic sealing core for the Latticra project.

The current implementation uses established open-source cryptographic primitives through `libsodium`:

- XChaCha20-Poly1305 for authenticated encryption
- BLAKE2b for transcript hashing and seal identifiers
- Ed25519ph for transcript proof/signature verification

Conceptually:

    SealΛ(m) := (c, τ, π)

    c = XChaCha20-Poly1305(k_msg, nonce, m, AD)
    τ = BLAKE2b(AD || c)
    π = Ed25519ph(prefix || τ || c)
    Δ = BLAKE2b(c || π || τ)

This repository does not claim to introduce a new cryptographic primitive. It is a protocol scaffold built from reviewed primitives.

## Repository Layout

    .
    ├── LICENSE
    ├── README.md
    ├── Makefile
    ├── .gitignore
    └── lcc.c

## Dependencies

Fedora:

    sudo dnf install -y gcc make pkgconf-pkg-config libsodium-devel

## Build

    make

This should produce:

    ./lcc

## Self-test

    make check

Expected output:

    selftest=ok

## Usage

Generate a local key directory:

    ./lcc keygen keys

This creates:

    keys/lcc.key
    keys/lcc.sign.pk
    keys/lcc.sign.sk

Seal a file:

    printf 'Latticra cryptographic core is alive.\n' > msg.txt
    ./lcc seal keys/lcc.key keys/lcc.sign.sk msg.txt msg.lcc

Inspect a sealed file:

    ./lcc inspect msg.lcc

Open a sealed file:

    ./lcc open keys/lcc.key keys/lcc.sign.pk msg.lcc msg.out

Verify the opened file matches the original:

    cmp msg.txt msg.out && echo verified

## Security Notes

Do not commit secret material.

Never commit:

- `keys/`
- `*.key`
- `*.sk`

The public verification key `lcc.sign.pk` may be shared. The symmetric key and signing secret key must remain private.

## Current Protocol Model

The current LCC seal format contains:

- a compact header
- an XChaCha20-Poly1305 ciphertext
- a BLAKE2b transcript hash
- an Ed25519ph transcript signature
- a derived seal identifier

High-level mapping:

    Λ = Latticra domain-separated lattice context
    Σ = signature/proof context
    κ = symmetric master key
    r = XChaCha20 nonce
    c = authenticated ciphertext
    τ = transcript hash
    π = transcript proof/signature
    Δ = seal identifier

## Status

Experimental research implementation.

Not independently audited.

Not recommended yet for production security boundaries.

## Intended Direction

Planned future work may include:

- streaming file encryption
- detached public verification mode
- key rotation
- stronger file format documentation
- test vectors
- fuzzing
- CI builds
- post-quantum extension path using standardized PQC primitives
