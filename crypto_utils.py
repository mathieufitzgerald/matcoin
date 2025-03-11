#!/usr/bin/env python3
"""
crypto_utils.py

Basic cryptographic helpers: double_sha256, hash160, base58 with check, etc.
"""

import hashlib
import base58

def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def hash160(b: bytes) -> bytes:
    sha = hashlib.sha256(b).digest()
    rip = hashlib.new('ripemd160')
    rip.update(sha)
    return rip.digest()

def base58_check_encode(prefix: bytes, payload: bytes) -> str:
    """
    Returns base58-check of prefix+payload+checksum
    """
    data = prefix + payload
    checksum = double_sha256(data)[:4]
    return base58.b58encode(data + checksum).decode('utf-8')

def base58_check_decode(s: str) -> bytes:
    """
    Decodes base58-check string into raw bytes: prefix+payload
    """
    raw = base58.b58decode(s)
    data, csum = raw[:-4], raw[-4:]
    if double_sha256(data)[:4] != csum:
        raise ValueError("Invalid base58 checksum")
    return data
