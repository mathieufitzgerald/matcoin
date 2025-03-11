#!/usr/bin/env python3
"""
blockchain_data.py

Basic data structures for transactions and blocks, plus merkle root, TX validation, etc.
"""

import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Tuple
from crypto_utils import double_sha256
import logging

logger = logging.getLogger("MattCoinData")

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
        raw = self.serialize()
        return double_sha256(raw).hex()

    def serialize(self) -> bytes:
        # For demonstration, just JSON:
        j_in = []
        for i in self.tx_in:
            j_in.append({
                "prev_tx_id": i.prev_tx_id,
                "prev_out_index": i.prev_out_index,
                "script_sig": i.script_sig,
                "sequence": i.sequence
            })
        j_out = []
        for o in self.tx_out:
            j_out.append({
                "value": o.value,
                "script_pubkey": o.script_pubkey
            })
        d = {
            "version": self.version,
            "tx_in": j_in,
            "tx_out": j_out,
            "lock_time": self.lock_time,
            "timestamp": self.timestamp
        }
        return json.dumps(d, sort_keys=True).encode('utf-8')

@dataclass
class BlockHeader:
    version: int
    prev_block_hash: str
    merkle_root: str
    timestamp: float
    bits: int
    nonce: int

    def block_hash(self) -> str:
        return double_sha256(self.serialize_header()).hex()

    def serialize_header(self) -> bytes:
        obj = {
            "version": self.version,
            "prev_block_hash": self.prev_block_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "bits": self.bits,
            "nonce": self.nonce
        }
        return json.dumps(obj, sort_keys=True).encode('utf-8')

@dataclass
class Block:
    header: BlockHeader
    transactions: List[Transaction] = field(default_factory=list)

    def block_hash(self) -> str:
        return self.header.block_hash()

def merkle_root(txs: List[Transaction]) -> str:
    if not txs:
        return "0" * 64
    hashes = [bytes.fromhex(tx.tx_id()) for tx in txs]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        new_hashes = []
        for i in range(0, len(hashes), 2):
            new_hashes.append(double_sha256(hashes[i] + hashes[i+1]))
        hashes = new_hashes
    return hashes[0].hex()

def validate_transaction(tx: Transaction, utxo_set: Dict[Tuple[str,int], Tuple[int,str]]) -> bool:
    """
    Check that inputs are unspent, script matches up, sum(in) >= sum(out).
    For demonstration, we skip real script execution and just do address matching, etc.
    """
    total_in = 0
    for i in tx.tx_in:
        key = (i.prev_tx_id, i.prev_out_index)
        if key not in utxo_set:
            logger.debug("validate_transaction: input not in UTXO set => fail")
            return False
        (val, spk) = utxo_set[key]
        total_in += val
        # We skip real script validation. In real code, you'd check i.script_sig vs spk.

    total_out = sum(o.value for o in tx.tx_out)
    if total_out > total_in:
        logger.debug("validate_transaction: output sum > input sum => fail")
        return False
    return True
