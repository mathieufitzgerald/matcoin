#!/usr/bin/env python3
"""
p2p_node.py

Implements the Node class: a listening server, peer connections, 
handles messages like 'get_balance', 'tx', 'block', etc.
"""

import sys
import socket
import select
import json
import time
import threading
import logging
from typing import Optional
from chain_state import Chain, Mempool
from blockchain_data import Block, Transaction, TxInput, TxOutput
from constants import (
    MSG_VERSION, MSG_VERACK, MSG_TX, MSG_BLOCK,
    MSG_GET_BALANCE, MSG_BALANCE,
)
from config import (
    NETWORK_MAGIC, PROTOCOL_VERSION, USER_AGENT, SEED_NODES
)
from crypto_utils import double_sha256

logger = logging.getLogger("MattCoinNode")

def serialize_msg(obj: dict) -> bytes:
    data = json.dumps(obj).encode('utf-8')
    length = len(data).to_bytes(4, 'big')
    return NETWORK_MAGIC + length + data

def deserialize_msg(sock) -> Optional[dict]:
    try:
        # read magic
        magic = sock.recv(len(NETWORK_MAGIC))
        if magic != NETWORK_MAGIC:
            return None
        # read length
        length_bytes = sock.recv(4)
        if len(length_bytes) < 4:
            return None
        length = int.from_bytes(length_bytes, 'big')
        # read payload
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode('utf-8'))
    except:
        return None

def tx_from_dict(d: dict) -> Transaction:
    """
    Convert a dict to a Transaction object (reverse of what wallet might send).
    """
    ver = d["version"]
    tx_in_raw = d["tx_in"]
    tx_out_raw = d["tx_out"]
    lock_time = d["lock_time"]
    timestamp = d["timestamp"]

    # The wallet code in "wallet_gui.py" or "wallet.py" typically sends 
    # "tx_in": [txid, out_idx, script_sig, txid, out_idx, script_sig, ...]
    # So we need to parse it in pairs/triples:
    inputs = []
    for i in range(0, len(tx_in_raw), 3):
        prev_tx_id = tx_in_raw[i]
        prev_idx = int(tx_in_raw[i+1])
        script_sig = tx_in_raw[i+2]
        ti = TxInput(prev_tx_id, prev_idx, script_sig)
        inputs.append(ti)

    outputs = []
    for j in range(0, len(tx_out_raw), 2):
        val = tx_out_raw[j]
        spk = tx_out_raw[j+1]
        to = TxOutput(val, spk)
        outputs.append(to)

    return Transaction(ver, inputs, outputs, lock_time, timestamp)

def block_from_dict(d: dict) -> Block:
    hdr_data = d["header"]
    from blockchain_data import BlockHeader
    bh = BlockHeader(
        version=hdr_data["version"],
        prev_block_hash=hdr_data["prev_block_hash"],
        merkle_root=hdr_data["merkle_root"],
        timestamp=hdr_data["timestamp"],
        bits=hdr_data["bits"],
        nonce=hdr_data["nonce"]
    )
    tx_list = []
    for txd in d["transactions"]:
        tx_list.append(tx_from_dict({
            "version": txd["version"],
            "tx_in": txd["tx_in"],
            "tx_out": txd["tx_out"],
            "lock_time": txd["lock_time"],
            "timestamp": txd["timestamp"]
        }))
    return Block(bh, tx_list)

class Node:
    def __init__(self, host: str, port: int, chain: Chain, mempool: Mempool, seed=None):
        self.host = host
        self.port = port
        self.chain = chain
        self.mempool = mempool
        self.peers = set()
        if seed:
            self.peers.add(seed)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(8)

        self.stop_event = threading.Event()
        threading.Thread(target=self.server_loop, daemon=True).start()

        # connect to seeds
        for s in SEED_NODES:
            self.peers.add(s)
        threading.Thread(target=self.connect_loop, daemon=True).start()
        threading.Thread(target=self.peer_gossip_loop, daemon=True).start()

        logger.info(f"Node started on {self.host}:{self.port} with {len(self.peers)} seeds/peers")

    def server_loop(self):
        while not self.stop_event.is_set():
            r, _, _ = select.select([self.sock], [], [], 1)
            if self.sock in r:
                conn, addr = self.sock.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def handle_client(self, conn, addr):
        while not self.stop_event.is_set():
            msg = deserialize_msg(conn)
            if not msg:
                break
            self.handle_message(msg, conn, addr)
        conn.close()

    def connect_loop(self):
        while not self.stop_event.is_set():
            for peer in list(self.peers):
                host, p = peer
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((host, p))
                    version_msg = {
                        "type": MSG_VERSION,
                        "version": PROTOCOL_VERSION,
                        "user_agent": USER_AGENT,
                        "port": self.port
                    }
                    s.sendall(serialize_msg(version_msg))
                    s.close()
                except:
                    pass
            time.sleep(30)

    def peer_gossip_loop(self):
        while not self.stop_event.is_set():
            # In a real node, you'd broadcast new blocks/txs, request data, etc.
            time.sleep(15)

    def send_message(self, conn, obj: dict):
        data = serialize_msg(obj)
        conn.sendall(data)

    def broadcast(self, obj: dict):
        for (h, p) in list(self.peers):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((h, p))
                s.sendall(serialize_msg(obj))
                s.close()
            except:
                pass

    def handle_message(self, msg: dict, conn, addr):
        mtype = msg.get("type")
        logger.debug("handle_message: got type=%s from %s", mtype, addr)

        if mtype == MSG_VERSION:
            their_port = msg.get("port", None)
            if their_port is not None:
                self.peers.add((addr[0], their_port))
            verack = {"type": MSG_VERACK}
            self.send_message(conn, verack)

        elif mtype == MSG_VERACK:
            pass

        elif mtype == MSG_GET_BALANCE:
            address = msg.get("address")
            logger.debug("Received get_balance for address=%s", address)
            bal = self.chain.get_balance(address)
            resp = {
                "type": MSG_BALANCE,
                "address": address,
                "balance": bal,
                "height": self.chain.height
            }
            self.send_message(conn, resp)

        elif mtype == MSG_TX:
            # wallet broadcast new TX
            tx_data = msg.get("data")
            tx = tx_from_dict(tx_data)
            logger.debug("Received TX from %s => %s", addr, tx.tx_id())
            # validate & add to mempool
            # For a real node, we'd do check: if validate_transaction(tx, self.chain.utxo_set)
            self.mempool.add_transaction(tx)
            # broadcast to peers
            forward = {
                "type": MSG_TX,
                "data": tx_data
            }
            self.broadcast(forward)

        elif mtype == MSG_BLOCK:
            block_data = msg.get("data")
            blk = block_from_dict(block_data)
            logger.debug("Received BLOCK from %s => %s", addr, blk.block_hash())
            # add to chain
            accepted = self.chain.add_block(blk, skip_pow=False)
            if accepted:
                # remove confirmed TXs from mempool
                for tx in blk.transactions[1:]:
                    self.mempool.remove_transaction(tx.tx_id())
                # broadcast
                fwd = {
                    "type": MSG_BLOCK,
                    "data": block_data
                }
                self.broadcast(fwd)

        else:
            logger.debug("Unknown or unhandled message type: %s", mtype)

    def shutdown(self):
        self.stop_event.set()
        self.sock.close()
