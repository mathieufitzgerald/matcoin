#!/usr/bin/env python3
"""
chain_state.py

Contains the Chain class that stores blocks, manages UTXOs, enforces consensus
(rudimentary difficulty, halving, etc.), plus a Mempool class for pending TXs.
"""

import time
import logging
from typing import Dict, Tuple, List
from dataclasses import dataclass, field

from blockchain_data import Block, BlockHeader, Transaction, TxInput, TxOutput, merkle_root, validate_transaction
from config import (
    INITIAL_DIFFICULTY,
    BLOCK_TARGET_TIME,
    DIFFICULTY_ADJUST_INTERVAL,
    HALVING_INTERVAL,
    INITIAL_BLOCK_REWARD,
)
from crypto_utils import double_sha256
logger = logging.getLogger("MattCoin")

@dataclass
class UTXOEntry:
    value: int
    script_pubkey: str

class Chain:
    """
    Maintains the best chain of blocks, the UTXO set, etc.
    """
    def __init__(self):
        # block storage: block_hash -> Block
        self.blocks = {}
        # chain tip:
        self.tip = None
        # chain height:
        self.height = 0
        # difficulty (bits or target):
        self.current_difficulty = INITIAL_DIFFICULTY
        # utxo set: (txid, out_idx) -> (value, script_pubkey)
        self.utxo_set: Dict[Tuple[str,int], Tuple[int,str]] = {}

        # create genesis block
        self.init_genesis_block()

    def init_genesis_block(self):
        # create a "dummy" genesis block
        from config import GENESIS_COINBASE_SCRIPT
        coinbase_in = TxInput("0"*64, 0, GENESIS_COINBASE_SCRIPT)
        coinbase_out = TxOutput(INITIAL_BLOCK_REWARD, "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG")
        genesis_tx = Transaction(1, [coinbase_in], [coinbase_out])
        mr = merkle_root([genesis_tx])
        hdr = BlockHeader(
            version=1,
            prev_block_hash="0"*64,
            merkle_root=mr,
            timestamp=time.time(),
            bits=self.current_difficulty,
            nonce=0
        )
        genesis_block = Block(hdr, [genesis_tx])

        # For "production," you might embed a valid PoW in the genesis block. We'll skip that.
        accepted = self.add_block(genesis_block)
        if accepted:
            logger.info("Genesis block created at height 1.")
        else:
            logger.warning("Genesis block was not accepted?")

    def add_block(self, block: Block) -> bool:
        # check PoW
        block_hash = block.block_hash()
        block_hash_val = int(block_hash, 16)
        if block_hash_val > self.current_difficulty:
            logger.warning("Block fails PoW check: %s", block_hash)
            return False

        # check merkle root
        calc_mr = merkle_root(block.transactions)
        if calc_mr != block.header.merkle_root:
            logger.warning("Block merkle root mismatch.")
            return False

        # check prev block
        if block.header.prev_block_hash not in self.blocks and block.header.prev_block_hash != "0"*64:
            logger.warning("Unknown prev block hash: %s", block.header.prev_block_hash)
            return False

        # validate transactions
        if not self.validate_block_txs(block):
            logger.warning("Block transaction validation failed.")
            return False

        # store the block
        self.blocks[block_hash] = block

        # if it builds on tip or if tip is None
        if (self.tip is None) or (block.header.prev_block_hash == self.tip) or (block.header.prev_block_hash == "0"*64):
            self.tip = block_hash
            self.height += 1
            # update UTXOs
            self.update_utxos_with_block(block)
            # adjust difficulty? (omitted real logic for brevity)
            # handle halving? ...
            return True
        else:
            # This might be a side chain. Real logic is more complex
            return True  # we'll accept but not make it active chain

    def validate_block_txs(self, block: Block) -> bool:
        if len(block.transactions) < 1:
            return False
        # check coinbase
        coinbase_tx = block.transactions[0]
        if len(coinbase_tx.tx_in) != 1:
            return False
        # check that coinbase out <= block reward
        block_reward = self.block_reward()
        coinbase_out_val = sum(o.value for o in coinbase_tx.tx_out)
        if coinbase_out_val > block_reward:
            return False

        # check all other TX
        for tx in block.transactions[1:]:
            if not validate_transaction(tx, self.utxo_set):
                return False
        return True

    def update_utxos_with_block(self, block: Block):
        for tx in block.transactions:
            txid = tx.tx_id()
            # remove spent
            for inp in tx.tx_in:
                k = (inp.prev_tx_id, inp.prev_out_index)
                if k in self.utxo_set:
                    del self.utxo_set[k]
            # add new
            for idx, outp in enumerate(tx.tx_out):
                self.utxo_set[(txid, idx)] = (outp.value, outp.script_pubkey)

    def block_reward(self) -> int:
        halvings = (self.height - 1) // HALVING_INTERVAL
        reward = INITIAL_BLOCK_REWARD >> halvings
        if reward < 1:
            reward = 1
        return reward

    def get_block_hashes(self) -> List[str]:
        """Return a list of block hashes in the chain (not necessarily in order)"""
        return list(self.blocks.keys())

    def get_balance(self, address_hex: str) -> int:
        """
        Sum all UTXOs that have script_pubkey referencing address_hex
        E.g. "OP_DUP OP_HASH160 <address_hex> OP_EQUALVERIFY OP_CHECKSIG"
        """
        total = 0
        for (txid, idx), (val, spk) in self.utxo_set.items():
            parts = spk.split()
            if len(parts) == 5 and parts[2] == address_hex:
                total += val
        return total

class Mempool:
    """
    Holds unconfirmed transactions. Provides a method to select transactions for mining, etc.
    """
    def __init__(self):
        self.pool = {}  # txid -> Transaction
        self.size = 0   # approximate memory usage

    def add_transaction(self, tx: Transaction):
        txid = tx.tx_id()
        if txid in self.pool:
            return
        raw_size = len(tx.serialize())
        # In a real node, check fees, priorities, spam, etc.
        self.pool[txid] = tx
        self.size += raw_size

    def remove_transaction(self, txid: str):
        if txid in self.pool:
            raw_size = len(self.pool[txid].serialize())
            del self.pool[txid]
            self.size -= raw_size

    def select_transactions_for_block(self, limit=500_000) -> List[Transaction]:
        # super naive: pick everything up to the limit
        selected = []
        total_size = 0
        for txid, tx in list(self.pool.items()):
            s = len(tx.serialize())
            if total_size + s <= limit:
                selected.append(tx)
                total_size += s
        return selected
