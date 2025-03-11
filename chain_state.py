#!/usr/bin/env python3
"""
chain_state.py

Stores the Chain (blocks, UTXOs) and Mempool. 
Implements skip-PoW for genesis so it's accepted, plus get_balance for the wallet.
"""

import time
import logging
from typing import Dict, Tuple, List
from dataclasses import dataclass, field

from blockchain_data import Block, BlockHeader, Transaction, TxInput, TxOutput, merkle_root, validate_transaction
from config import (
    INITIAL_DIFFICULTY,
    GENESIS_COINBASE_SCRIPT,
    INITIAL_BLOCK_REWARD,
    HALVING_INTERVAL
)
logger = logging.getLogger("MattCoin")

@dataclass
class Mempool:
    pool: Dict[str, Transaction] = field(default_factory=dict)
    size: int = 0

    def add_transaction(self, tx: Transaction):
        txid = tx.tx_id()
        if txid in self.pool:
            return
        raw_size = len(tx.serialize())
        self.pool[txid] = tx
        self.size += raw_size

    def remove_transaction(self, txid: str):
        if txid in self.pool:
            raw_size = len(self.pool[txid].serialize())
            del self.pool[txid]
            self.size -= raw_size

    def select_transactions_for_block(self, limit=500_000) -> List[Transaction]:
        selected = []
        total_size = 0
        for txid, tx in list(self.pool.items()):
            s = len(tx.serialize())
            if total_size + s <= limit:
                selected.append(tx)
                total_size += s
        return selected

class Chain:
    def __init__(self):
        self.blocks = {}  # block_hash -> Block
        self.tip = None
        self.height = 0
        self.current_difficulty = INITIAL_DIFFICULTY
        self.utxo_set: Dict[Tuple[str,int], Tuple[int,str]] = {}

        self.init_genesis_block()

    def init_genesis_block(self):
        # Create genesis block
        coinbase_in = TxInput("0"*64, 0, GENESIS_COINBASE_SCRIPT)
        coinbase_out = TxOutput(INITIAL_BLOCK_REWARD, "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG")
        genesis_tx = Transaction(1, [coinbase_in], [coinbase_out])
        mr = merkle_root([genesis_tx])
        from config import NETWORK_MAGIC
        hdr = BlockHeader(
            version=1,
            prev_block_hash="0"*64,
            merkle_root=mr,
            timestamp=time.time(),
            bits=self.current_difficulty,
            nonce=0
        )
        genesis_block = Block(hdr, [genesis_tx])

        # Accept genesis without PoW
        accepted = self.add_block(genesis_block, skip_pow=True)
        if accepted:
            logger.info("Genesis block created at height 1.")
        else:
            logger.warning("Genesis block was not accepted?")

    def add_block(self, block: Block, skip_pow=False) -> bool:
        bhash = block.block_hash()
        bhval = int(bhash, 16)

        if not skip_pow:
            # normal block: check PoW
            if bhval > self.current_difficulty:
                logger.warning("Block fails PoW check: %s", bhash)
                return False
        else:
            logger.info("Skipping PoW check for genesis block.")

        # check merkle root
        calc_mr = merkle_root(block.transactions)
        if calc_mr != block.header.merkle_root:
            logger.warning("Block merkle root mismatch.")
            return False

        # check parent
        if block.header.prev_block_hash not in self.blocks and block.header.prev_block_hash != "0"*64:
            logger.warning("Unknown prev block hash %s", block.header.prev_block_hash)
            return False

        # validate coinbase + other tx
        if not self.validate_block_txs(block):
            logger.warning("Block transaction validation failed.")
            return False

        # store the block
        self.blocks[bhash] = block

        # if it builds on tip or tip is None
        if (self.tip is None) or (block.header.prev_block_hash == self.tip) or (block.header.prev_block_hash == "0"*64):
            self.tip = bhash
            self.height += 1
            self.update_utxos(block)
        else:
            # side chain scenario
            pass

        return True

    def validate_block_txs(self, block: Block) -> bool:
        if len(block.transactions) < 1:
            return False
        coinbase = block.transactions[0]
        if len(coinbase.tx_in) != 1:
            return False
        # block reward
        block_reward = self.block_reward()
        coinbase_out_val = sum(o.value for o in coinbase.tx_out)
        if coinbase_out_val > block_reward:
            return False

        # check normal tx
        for tx in block.transactions[1:]:
            if not validate_transaction(tx, self.utxo_set):
                return False
        return True

    def update_utxos(self, block: Block):
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
        r = INITIAL_BLOCK_REWARD >> halvings
        return r if r > 0 else 1

    def get_balance(self, address_hex: str) -> int:
        """
        Sum all UTXOs that match script containing 'address_hex' after OP_HASH160
        e.g. OP_DUP OP_HASH160 <address_hex> OP_EQUALVERIFY OP_CHECKSIG
        """
        total = 0
        for (txid, idx), (val, spk) in self.utxo_set.items():
            parts = spk.split()
            if len(parts) == 5 and parts[2] == address_hex:
                total += val
        return total
