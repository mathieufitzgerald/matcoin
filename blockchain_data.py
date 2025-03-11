#!/usr/bin/env python3
"""
blockchain_data.py

Contains data structures for Block, Transaction, TxInput, TxOutput, plus logic
for serialization and hashing (Merkle root, block header, etc.).
"""

import time
import json
from dataclasses import dataclass, field
from typing import List
from crypto_utils import double_sha256
from script_engine import eval_script

@dataclass
class TxInput:
    prev_tx_id: str
    prev_out_index: int
    script_sig: str
    sequence: int = 0xFFFFFFFF

@dataclass
class TxOutput:
    value: int
    script_pubkey: str

@dataclass
class Transaction:
    version: int
    tx_in: List[TxInput]
    tx_out: List[TxOutput]
    lock_time: int = 0
    timestamp: float = field(default_factory=time.time)

    def tx_id(self) -> str:
        """
        TXID is double-sha256 of its "serialized" form. (Hash is displayed LE in Bitcoin, but we'll do big-end here.)
        """
        raw = self.serialize()
        return double_sha256(raw).hex()

    def serialize(self) -> bytes:
        """
        Full serialization including scriptSigs. For TXID we typically do this in a certain format.
        """
        # We'll just store in JSON for demonstration
        j_in = []
        for i in self.tx_in:
            j_in.append({
                'prev_tx_id': i.prev_tx_id,
                'prev_out_index': i.prev_out_index,
                'script_sig': i.script_sig,
                'sequence': i.sequence
            })
        j_out = []
        for o in self.tx_out:
            j_out.append({
                'value': o.value,
                'script_pubkey': o.script_pubkey
            })
        obj = {
            'version': self.version,
            'tx_in': j_in,
            'tx_out': j_out,
            'lock_time': self.lock_time,
            'timestamp': self.timestamp
        }
        return json.dumps(obj, sort_keys=True).encode('utf-8')

    def copy_for_signing(self, in_idx: int):
        """
        Create a new Transaction object with blank scriptSig for the input in_idx.
        This is used in the script verification process.
        """
        tx_copy = Transaction(
            version=self.version,
            tx_in=[],
            tx_out=[o for o in self.tx_out],
            lock_time=self.lock_time,
            timestamp=self.timestamp
        )
        for i, inp in enumerate(self.tx_in):
            if i == in_idx:
                tx_copy.tx_in.append(TxInput(inp.prev_tx_id, inp.prev_out_index, "", inp.sequence))
            else:
                tx_copy.tx_in.append(TxInput(inp.prev_tx_id, inp.prev_out_index, inp.script_sig, inp.sequence))
        return tx_copy

    def serialize_for_signing(self) -> bytes:
        """
        For a typical SIGHASH_ALL, we might append 0x01000000. We'll keep it simple.
        """
        return self.serialize()


@dataclass
class BlockHeader:
    version: int
    prev_block_hash: str
    merkle_root: str
    timestamp: float
    bits: int
    nonce: int

    def block_hash(self) -> str:
        h = self.serialize_header()
        return double_sha256(h).hex()

    def serialize_header(self) -> bytes:
        obj = {
            'version': self.version,
            'prev_block_hash': self.prev_block_hash,
            'merkle_root': self.merkle_root,
            'timestamp': self.timestamp,
            'bits': self.bits,
            'nonce': self.nonce
        }
        return json.dumps(obj, sort_keys=True).encode('utf-8')


@dataclass
class Block:
    header: BlockHeader
    transactions: List[Transaction]

    def block_hash(self) -> str:
        return self.header.block_hash()

def merkle_root(txs: List[Transaction]) -> str:
    if not txs:
        return "0"*64
    hashes = [bytes.fromhex(tx.tx_id()) for tx in txs]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        new_hashes = []
        for i in range(0, len(hashes), 2):
            new_hashes.append(double_sha256(hashes[i] + hashes[i+1]))
        hashes = new_hashes
    return hashes[0].hex()

def validate_transaction(tx: Transaction, utxo_set) -> bool:
    """
    Check inputs are unspent, scripts pass, and input sum >= output sum
    'utxo_set' is a dict: (txid, out_idx) -> (value, script_pubkey)
    """
    total_in = 0
    for i, inp in enumerate(tx.tx_in):
        key = (inp.prev_tx_id, inp.prev_out_index)
        if key not in utxo_set:
            return False
        (val, pub_script) = utxo_set[key]
        # Evaluate script:
        # We'll treat script_sig & script_pubkey as "bytes"
        # Our approach: store them as strings, decode them in the script engine
        sig_bytes = inp.script_sig.encode('utf-8')
        pub_bytes = pub_script.encode('utf-8')
        if not eval_script(sig_bytes, pub_bytes, tx, i):
            return False
        total_in += val

    total_out = sum(o.value for o in tx.tx_out)
    if total_out > total_in:
        return False
    return True
