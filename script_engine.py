
#!/usr/bin/env python3
"""
script_engine.py

Implements a simplified stack-based Script interpreter with a subset of Bitcoin opcodes.
This is more thorough than the minimal P2PKH checks, but still not 100% of real Bitcoin's script.
"""

import sys
import hashlib
import ecdsa
from crypto_utils import hash160, double_sha256

# Subset of opcodes:
OP_DUP = b'\x76'
OP_HASH160 = b'\xa9'
OP_EQUAL = b'\x87'
OP_EQUALVERIFY = b'\x88'
OP_CHECKSIG = b'\xac'

def eval_script(script_sig: bytes, script_pubkey: bytes, tx_to, in_idx: int) -> bool:
    """
    Evaluate scriptSig + scriptPubKey in a single combined stack execution.
    'tx_to' is the transaction being validated, 'in_idx' is the input index.
    For simplicity, we only handle a subset of standard P2PKH flow.
    """
    stack = []
    altstack = []

    # Combine scripts
    full_script = script_sig + script_pubkey

    # In real Bitcoin, scripts are parsed as chunks, opcodes, etc. We'll do a simpler approach:
    # We'll assume script_sig is <sig> <pubkey> for P2PKH.
    # We'll assume script_pubkey is OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    # For demonstration, let's parse them as space-separated hex or raw opcodes.

    # Real parsing is complicated, but let's do an ad-hoc approach:
    try:
        # Ad-hoc parser: treat script_sig as "sig pubkey" in hex string. 
        # Then treat script_pubkey as opcodes and data. 
        # This is more of a placeholder for a real script machine.
        # We'll interpret if the pubkey-hash matches, then check the signature.

        # Convert script_sig from space-separated hex if possible:
        script_sig_str = script_sig.decode('utf-8', errors='ignore')
        script_pub_str = script_pubkey.decode('utf-8', errors='ignore')

        # Example: script_sig = "3045022100abcd... 024e8c..."
        # script_pubkey = "76 a9 <pubkeyhash> 88 ac" or something similar
        # We'll do a naive check:

        # parse scriptSig
        parts_sig = script_sig_str.split()
        if len(parts_sig) < 2:
            return False
        signature_hex, pubkey_hex = parts_sig[0], parts_sig[1]
        signature = bytes.fromhex(signature_hex)
        pubkey = bytes.fromhex(pubkey_hex)

        # parse scriptPubKey (naive)
        parts_pub = script_pub_str.split()
        # Typically: OP_DUP (76), OP_HASH160 (a9), <hash>, OP_EQUALVERIFY(88), OP_CHECKSIG(ac)
        # We'll find the <hash> in parts_pub[2]
        if len(parts_pub) < 5:
            return False
        embedded_hash_hex = parts_pub[2]

        # OP_DUP + OP_HASH160 => compute hash160 of pubkey, compare with embedded_hash_hex
        pub_hash = hash160(pubkey).hex()
        if pub_hash != embedded_hash_hex:
            return False

        # OP_CHECKSIG => verify signature
        # We'll do "SIGHASH_ALL" approach: re-hash the TX with scriptSig blank in that input
        tx_copy = tx_to.copy_for_signing(in_idx)
        msg_hash = double_sha256(tx_copy.serialize_for_signing())

        vk = ecdsa.VerifyingKey.from_string(pubkey, curve=ecdsa.SECP256k1)
        vk.verify(signature, msg_hash, hashfunc=hashlib.sha256)

        return True

    except Exception as e:
        return False
