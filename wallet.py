#!/usr/bin/env python3
"""
wallet.py

Provides functionality for:
- Generating keypairs (ECDSA)
- Converting pubkey -> address
- Creating/sending transactions
- Possibly scanning chain for UTXOs to find your balance
"""

import os
import json
import time
import ecdsa
from typing import Optional, List
from crypto_utils import hash160, double_sha256, base58_check_encode, base58_check_decode
from blockchain_data import Transaction, TxInput, TxOutput

def generate_keypair() -> (bytes, bytes):
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return sk.to_string(), vk.to_string()

def pubkey_to_address(pubkey_bytes: bytes, prefix: bytes=b"\x00") -> str:
    """
    Real Bitcoin uses prefix=0x00 for mainnet P2PKH. Then we do base58-check encoding.
    """
    h160 = hash160(pubkey_bytes)
    return base58_check_encode(prefix, h160)

def sign_transaction(tx: Transaction, privkey: bytes, pubkey: bytes, input_index: int):
    """
    SIGHASH_ALL approach: we create a copy with blank script for input_index,
    then double-sha256 it, sign, store sig & pubkey in scriptSig.
    """
    # For brevity, we won't re-implement it here. The logic is similar to before.
    # Typically: tx_copy = tx.copy_for_signing(input_index)
    # msg_hash = double_sha256(tx_copy.serialize_for_signing())
    # sign with ecdsa
    pass

def create_transaction(utxos, to_address, amount, privkey, pubkey) -> Transaction:
    """
    Build a transaction spending the given utxos, sending 'amount' to 'to_address',
    plus a leftover 'change' output back to you if there's leftover.
    'utxos' is a list of (txid, vout, value).
    This is a naive approach. Real wallets do much more logic.
    """
    # sum up utxos
    total_in = 0
    inputs = []
    for (txid, vout, val) in utxos:
        total_in += val
        inputs.append(TxInput(txid, vout, ""))

    if total_in < amount:
        raise ValueError("Not enough funds in utxos")

    # scriptPubKey for the recipient
    # decode base58 if used. Let's assume 'to_address' is hex of hash160 for simplicity:
    # If to_address is a typical "1XYZ..." base58, decode it:
    # data = base58_check_decode(to_address) -> prefix + payload
    # hex160 = payload.hex()
    # script_pubkey = "OP_DUP OP_HASH160 {hex160} OP_EQUALVERIFY OP_CHECKSIG"
    # We'll just do a naive approach:
    script_pubkey_dest = f"OP_DUP OP_HASH160 {to_address} OP_EQUALVERIFY OP_CHECKSIG"

    # create output
    out_main = TxOutput(amount, script_pubkey_dest)

    # leftover => change
    leftover = total_in - amount
    # real wallet also subtracts fee
    # for demonstration, skip fees or do leftover -= fee
    if leftover < 0:
        raise ValueError("Not enough to cover amount + fees")

    # change output
    # your own address:
    my_hash160 = hash160(pubkey).hex()
    script_pubkey_change = f"OP_DUP OP_HASH160 {my_hash160} OP_EQUALVERIFY OP_CHECKSIG"
    out_change = TxOutput(leftover, script_pubkey_change)

    tx = Transaction(version=1, tx_in=inputs, tx_out=[out_main, out_change])

    # sign each input
    # for i,_ in enumerate(inputs):
    #    sign_transaction(tx, privkey, pubkey, i)

    return tx
