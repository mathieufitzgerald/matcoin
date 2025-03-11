#!/usr/bin/env python3
"""
miner.py

A simple CPU miner script. 
Usage: python miner.py <node_host> <node_port> <coinbase_hash160>

It will:
- Connect to the node for the latest chain tip 
  (In real code, you'd want an RPC or message for that, we do a naive approach here).
- Build a block with a coinbase paying <coinbase_hash160>.
- Increment nonce until hash <= difficulty. 
- Broadcast the block to the node with "type": "block".
"""

import sys
import time
import random
import socket
import json
import hashlib
from typing import Optional

from crypto_utils import double_sha256
from blockchain_data import Block, BlockHeader, Transaction, TxInput, TxOutput, merkle_root
from config import NETWORK_MAGIC, INITIAL_BLOCK_REWARD
from constants import MSG_VERSION, MSG_BLOCK, PROTOCOL_VERSION, USER_AGENT
import base58

def recvall(conn, length):
    buf = b''
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def send_msg(conn, obj: dict):
    data = json.dumps(obj).encode('utf-8')
    length = len(data).to_bytes(4, 'big')
    conn.sendall(NETWORK_MAGIC + length + data)

def recv_msg(conn) -> Optional[dict]:
    # read magic
    magic = recvall(conn, len(NETWORK_MAGIC))
    if magic != NETWORK_MAGIC:
        return None
    length_bytes = recvall(conn, 4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, 'big')
    data = recvall(conn, length)
    if not data:
        return None
    return json.loads(data.decode('utf-8'))

def main():
    if len(sys.argv) < 4:
        print("Usage: python miner.py <node_host> <node_port> <coinbase_hash160>")
        sys.exit(1)

    node_host = sys.argv[1]
    node_port = int(sys.argv[2])
    coinbase_hash_hex = sys.argv[3]

    while True:
        # Step 1: fetch current tip from the node. We'll do a hack:
        # we assume the node has a "get_tip" message or we can store the tip in a local var. 
        # Here, we'll cheat by storing the last known tip in a global, or do a one-block approach.
        # For demonstration, let's just ask the node for "get_tip" or "get_height" if implemented.
        # If not, we might skip and just guess the tip from local data.

        # Let's do a hack: We'll do "type": "version" to connect, but
        # in real code you'd want an actual "get_tip" message. We'll skip here for brevity.

        # We'll guess the last block from the node by a "fake" approach. 
        # We'll just do a single-block approach if no easy get. 
        # For a robust approach, you'd actually fetch the chain tip or store it locally.
        # We'll skip that and assume the node's chain tip is known or is the genesis block. 

        # We'll also guess the node's difficulty from config or store it. 
        # Let's do a big target: 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        target = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        # Step 2: Build a block using the node's current tip (we'll guess it is stored in node or is "0"*64 if genesis).
        # This is a naive approach.
        prev_hash = "0"*64  # in real code we'd query the node's .tip
        # coinbase tx
        coinbase_in = TxInput("0"*64, 0, "miner coinbase input")
        # no fees, just block reward
        coinbase_out = TxOutput(INITIAL_BLOCK_REWARD, f"OP_DUP OP_HASH160 {coinbase_hash_hex} OP_EQUALVERIFY OP_CHECKSIG")
        coinbase_tx = Transaction(version=1, tx_in=[coinbase_in], tx_out=[coinbase_out])

        block_txs = [coinbase_tx]  # skipping mempool TXs

        mr = merkle_root(block_txs)
        hdr = BlockHeader(
            version=1,
            prev_block_hash=prev_hash,
            merkle_root=mr,
            timestamp=time.time(),
            bits=target,  # For demonstration, store target in 'bits'
            nonce=0
        )
        candidate_block = Block(hdr, block_txs)

        # Step 3: do PoW
        start_nonce = random.randint(0, 2**32-1)
        candidate_block.header.nonce = start_nonce
        print("Mining block on top of prev_hash =", prev_hash, " to address=", coinbase_hash_hex)
        loops = 0
        t0 = time.time()
        found = False
        while True:
            loops += 1
            h_val = int(candidate_block.block_hash(), 16)
            if h_val <= target:
                # found
                print(f"Found block! nonce={candidate_block.header.nonce}, hash={candidate_block.block_hash()}")
                found = True
                break
            else:
                candidate_block.header.nonce += 1
                if candidate_block.header.nonce - start_nonce > 200000:
                    break

        dt = time.time() - t0
        if found:
            # Step 4: broadcast it to the node
            msg = {
                "type": MSG_BLOCK,
                "data": block_to_dict(candidate_block)
            }
            # connect to node
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((node_host, node_port))
                send_msg(s, {"type": MSG_VERSION, "version": PROTOCOL_VERSION, "user_agent": USER_AGENT, "port":9999})
                _ = recv_msg(s)  # ignore verack
                send_msg(s, msg)
                s.close()
                print("Block broadcasted. Sleep 5s then keep mining.")
            except Exception as e:
                print("Failed to broadcast block:", e)

            time.sleep(5)
        else:
            print(f"No block found in {loops} tries after {dt:.2f}s, rebuilding candidate.")
            time.sleep(2)

def block_to_dict(b: Block) -> dict:
    return {
        "header": {
            "version": b.header.version,
            "prev_block_hash": b.header.prev_block_hash,
            "merkle_root": b.header.merkle_root,
            "timestamp": b.header.timestamp,
            "bits": b.header.bits,
            "nonce": b.header.nonce
        },
        "transactions": [
            {
                "version": tx.version,
                "tx_in": flatten_txins(tx.tx_in),
                "tx_out": flatten_txouts(tx.tx_out),
                "lock_time": tx.lock_time,
                "timestamp": tx.timestamp
            } for tx in b.transactions
        ]
    }

def flatten_txins(ins: list) -> list:
    arr = []
    for i in ins:
        arr.append(i.prev_tx_id)
        arr.append(i.prev_out_index)
        arr.append(i.script_sig)
    return arr

def flatten_txouts(outs: list) -> list:
    arr = []
    for o in outs:
        arr.append(o.value)
        arr.append(o.script_pubkey)
    return arr

if __name__ == "__main__":
    main()
