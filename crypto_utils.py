#!/usr/bin/env python3
"""
crypto_utils.py

Cryptographic and utility functions: double-sha256, ripemd160, base58, etc.
"""

import hashlib
import base58  # pip install base58
import ecdsa

def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def hash160(b: bytes) -> bytes:
    """RIPEMD160(SHA256(b))"""
    sha = hashlib.sha256(b).digest()
    rip = hashlib.new('ripemd160')
    rip.update(sha)
    return rip.digest()

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def base58_check_encode(prefix: bytes, payload: bytes) -> str:
    """
    Convert prefix + payload to Base58Check.
    prefix might be 1 byte (like 0x00 for mainnet pubkey-hash in real Bitcoin).
    """
    data = prefix + payload
    checksum = double_sha256(data)[:4]
    return base58.b58encode(data + checksum).decode('utf-8')

def base58_check_decode(s: str) -> bytes:
    """
    Decode Base58Check string to raw bytes. Return prefix + payload.
    """
    full = base58.b58decode(s)
    data, checksum = full[:-4], full[-4:]
    if double_sha256(data)[:4] != checksum:
        raise ValueError("Invalid base58 checksum")
    return data
