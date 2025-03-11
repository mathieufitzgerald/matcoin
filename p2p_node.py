#!/usr/bin/env python3
"""
p2p_node.py

Includes the "get_balance" handler.
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
    MSG_VERSION, MSG_VERACK, MSG_TX, MSG_BLOCK,
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
    data = json.dumps(obj).encode('utf-8')
    length = len(data).to_bytes(4, 'big')
    return NETWORK_MAGIC + length + data

def deserialize_msg(sock) -> Optional[dict]:
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

        threading.Thread(target=self.server_loop, daemon=True).start()

        # Connect to seeds
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
                host, port = peer
                try:
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
        while not self.stop_event.is_set():
            # placeholder
            time.sleep(15)

    def send_message(self, conn, obj: dict):
        data = serialize_msg(obj)
        conn.sendall(data)

    def broadcast(self, obj: dict):
        for (host, port) in list(self.peers):
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
        logger.debug("handle_message: got type=%s from %s", mtype, addr)

        if mtype == MSG_VERSION:
            their_port = msg.get("port", None)
            if their_port is not None:
                self.peers.add((addr[0], their_port))
            verack_msg = {"type": MSG_VERACK}
            self.send_message(conn, verack_msg)

        elif mtype == "get_balance":
            address = msg.get("address")
            logger.debug("Received get_balance for address=%s", address)
            bal = self.chain.get_balance(address)
            resp = {
                "type": "balance",
                "address": address,
                "balance": bal,
                "height": self.chain.height
            }
            self.send_message(conn, resp)

        elif mtype == MSG_VERACK:
            pass

        elif mtype == MSG_TX:
            tx_data = msg.get("data")
            logger.debug("Received new TX from %s. Data: %s", addr, tx_data)
            # parse -> validate -> mempool
            # You need code to reconstruct the Transaction object, do self.mempool.add_transaction(...).
            pass

        elif mtype == MSG_BLOCK:
            block_data = msg.get("data")
            logger.debug("Received new block from %s. Data: %s", addr, block_data)
            # parse -> chain.add_block -> if accepted, broadcast
            pass

        else:
            logger.debug("Unknown or unhandled message type: %s", mtype)

    def shutdown(self):
        self.stop_event.set()
        self.sock.close()
