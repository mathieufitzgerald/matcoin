#!/usr/bin/env python3
"""
p2p_node.py

Implements the Node class, which manages peer connections, message handling,
gossiping blocks & transactions, querying mempool, etc.
"""

import sys
import socket
import select
import json
import time
import threading
import logging
from typing import Optional
from blockchain_data import Block, Transaction
from chain_state import Chain, Mempool
from constants import (
    MSG_VERSION, MSG_VERACK, MSG_GETPEERS, MSG_PEERS,
    MSG_INV, MSG_GETDATA, MSG_BLOCK, MSG_TX, MSG_PING, MSG_PONG,
    INVENTORY_MSG_BLOCK, INVENTORY_MSG_TX,
)
from config import (
    NETWORK_MAGIC,
    PROTOCOL_VERSION,
    USER_AGENT,
    SEED_NODES,
)
from crypto_utils import double_sha256

logger = logging.getLogger("MattCoinNode")

def serialize_msg(obj: dict) -> bytes:
    """
    Convert a Python dict into a length-prefixed message with NETWORK_MAGIC.
    """
    data = json.dumps(obj).encode('utf-8')
    length = len(data).to_bytes(4, 'big')
    return NETWORK_MAGIC + length + data

def deserialize_msg(sock) -> Optional[dict]:
    """
    Read a single message from 'sock'. Return the dict or None if error.
    """
    try:
        header = sock.recv(len(NETWORK_MAGIC))
        if header != NETWORK_MAGIC:
            return None
        length_bytes = sock.recv(4)
        if len(length_bytes) < 4:
            return None
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode('utf-8'))
    except:
        return None

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

        # start listening thread
        threading.Thread(target=self.server_loop, daemon=True).start()

        # try connecting to seed nodes
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
                threading.Thread(target=self.handle_client, args=(conn,addr), daemon=True).start()

    def handle_client(self, conn, addr):
        while not self.stop_event.is_set():
            msg = deserialize_msg(conn)
            if not msg:
                break
            self.handle_message(msg, conn, addr)
        conn.close()

    def connect_loop(self):
        # periodical connect to known peers
        while not self.stop_event.is_set():
            for peer in list(self.peers):
                host, port = peer
                try:
                    # say hello
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((host, port))
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
        # gossip mempool or blocks to peers, etc.
        while not self.stop_event.is_set():
            # For demonstration, do nothing or broadcast new TX/blocks if we had them
            time.sleep(15)

    def send_message(self, conn, obj: dict):
        data = serialize_msg(obj)
        conn.sendall(data)

    def broadcast(self, obj: dict):
        for (host,port) in list(self.peers):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((host, port))
                s.sendall(serialize_msg(obj))
                s.close()
            except:
                pass

    def handle_message(self, msg: dict, conn, addr):
        mtype = msg.get("type")
        if mtype == MSG_VERSION:
            # peer handshake
            their_port = msg.get("port", None)
            if their_port is not None:
                self.peers.add((addr[0], their_port))
            verack_msg = {"type": MSG_VERACK}
            self.send_message(conn, verack_msg)

        elif mtype == MSG_VERACK:
            # no action needed
            pass

        elif mtype == MSG_TX:
            tx_data = msg.get("data")
            # We need to convert it to a Transaction object. We'll assume it's a dictionary.
            # Omitted here for brevity - see block_from_json or tx_from_json in prior code.
            # Validate & add to mempool.
            # ...
            pass

        elif mtype == MSG_BLOCK:
            block_data = msg.get("data")
            # Convert to Block object, chain.add_block(...).
            # If accepted, broadcast to peers.
            # ...
            pass

        elif mtype == "get_balance":
            address = msg.get("address")
            bal = self.chain.get_balance(address)
            height = self.chain.height
            resp = {
                "type": "balance",
                "address": address,
                "balance": bal,
                "height": height
            }
            self.send_message(conn, resp)

        elif mtype == "faucet":
            # cheat block awarding coins
            address = msg.get("address")
            # build a new block paying address
            # skip real PoW if you want a "faucet"
            pass

        # etc. for other message types

    def shutdown(self):
        self.stop_event.set()
        self.sock.close()
