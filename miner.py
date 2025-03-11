#!/usr/bin/env python3
"""
miner.py

Provides a simple CPU miner that:
- Builds a block template from the chain tip and mempool
- Tries random nonces until block_hash <= current_difficulty
- Broadcasts the found block

In a real node, this would be integrated or run as a separate thread.
"""

import time
import random
import logging
from blockchain_data import Block, BlockHeader, Transaction, TxInput, TxOutput, merkle_root
from config import INITIAL_BLOCK_REWARD
from chain_state import Chain, Mempool
from crypto_utils import double_sha256
from p2p_node import serialize_msg
from constants import MSG_BLOCK

logger = logging.getLogger("MattCoinMiner")

def mine_one_block(chain: Chain, mempool: Mempool, coinbase_address: str, node) -> bool:
    """
    Attempt to mine a block on top of chain.tip, using transactions from mempool.
    coinbase_address is the address that receives the block reward.
    'node' is used to broadcast the block if found.
    Return True if a block is mined, else False.
    """
    tip_hash = chain.tip
    if tip_hash is None:
        return False
    parent_block = chain.blocks[tip_hash]

    # gather TXs from mempool
    selected_txs = mempool.select_transactions_for_block()

    # coinbase TX
    coinbase_in = TxInput("0"*64, 0, "coinbase input")
    block_reward = chain.block_reward()
    # In a real system, you add transaction fees to this reward
    coinbase_out = TxOutput(block_reward, f"OP_DUP OP_HASH160 {coinbase_address} OP_EQUALVERIFY OP_CHECKSIG")
    coinbase_tx = Transaction(version=1, tx_in=[coinbase_in], tx_out=[coinbase_out])

    block_txs = [coinbase_tx] + selected_txs
    mr = merkle_root(block_txs)

    block_header = BlockHeader(
        version=1,
        prev_block_hash=tip_hash,
        merkle_root=mr,
        timestamp=time.time(),
        bits=chain.current_difficulty,
        nonce=0
    )
    candidate = Block(block_header, block_txs)
    target = chain.current_difficulty

    start_nonce = random.randint(0, 2**32-1)
    candidate.header.nonce = start_nonce
    loops = 0
    t0 = time.time()

    while True:
        loops += 1
        hval = int(candidate.block_hash(), 16)
        if hval <= target:
            # found block
            accepted = chain.add_block(candidate)
            if accepted:
                # remove from mempool
                for tx in selected_txs:
                    mempool.remove_transaction(tx.tx_id())
                # broadcast
                msg = {
                    "type": MSG_BLOCK,
                    "data": block_to_json(candidate)
                }
                node.broadcast(msg)
                dt = time.time() - t0
                logger.info(f"Found block {candidate.block_hash()} in {loops} tries, {dt:.2f}s")
                return True
            else:
                return False
        else:
            candidate.header.nonce += 1

        if candidate.header.nonce - start_nonce > 1000000:
            # rebuild candidate after some tries
            return False

def block_to_json(blk: Block) -> dict:
    """
    Convert block to dict for sending over p2p. 
    (In a real system, you'd match Bitcoin's wire format.)
    """
    return {
        "header": {
            "version": blk.header.version,
            "prev_block_hash": blk.header.prev_block_hash,
            "merkle_root": blk.header.merkle_root,
            "timestamp": blk.header.timestamp,
            "bits": blk.header.bits,
            "nonce": blk.header.nonce
        },
        "transactions": [
            {
                "version": tx.version,
                "tx_in": [
                    {
                        "prev_tx_id": i.prev_tx_id,
                        "prev_out_index": i.prev_out_index,
                        "script_sig": i.script_sig,
                        "sequence": i.sequence
                    } for i in tx.tx_in
                ],
                "tx_out": [
                    {
                        "value": o.value,
                        "script_pubkey": o.script_pubkey
                    } for o in tx.tx_out
                ],
                "lock_time": tx.lock_time,
                "timestamp": tx.timestamp
            }
            for tx in blk.transactions
        ]
    }
