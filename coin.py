#!/usr/bin/env python3


import sys
import socket
import threading
import time
import json
import hashlib
import select
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import ecdsa

# -------------------------------------------------------------------------
# CONFIG OPTIONS
# -------------------------------------------------------------------------
ENABLE_FAUCET = True  # If True, node supports a "faucet" command awarding free coins
FAUCET_REWARD = 50_0000_0000  # 50 MAT in "satoshis"

# -------------------------------------------------------------------------
# LOGGING SETUP
# -------------------------------------------------------------------------
logger = logging.getLogger("MattCoin")
logger.setLevel(logging.DEBUG)  # or logging.INFO for fewer messages
ch = logging.StreamHandler(sys.stdout)
fmt = logging.Formatter("[%(asctime)s] %(levelname)s - %(name)s - %(message)s")
ch.setFormatter(fmt)
logger.addHandler(ch)

# -------------------------------------------------------------------------
# CONSTANTS
# -------------------------------------------------------------------------
VERSION = 1
NETWORK_MAGIC = b"MATTCoin"
INITIAL_DIFFICULTY = 0x000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
COINBASE_VALUE = 50_0000_0000  # 50 MAT block reward
HALVING_INTERVAL = 100_000
MAX_BLOCK_SIZE = 1_000_000

# -------------------------------------------------------------------------
# DATA CLASSES
# -------------------------------------------------------------------------
@dataclass
class TxInput:
    tx_id: str
    output_index: int
    script_sig: str

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
        return double_sha256(self.serialize(True)).hex()

    def serialize(self, include_signatures=True) -> bytes:
        in_data = []
        for inp in self.tx_in:
            in_data.append(inp.tx_id)
            in_data.append(str(inp.output_index))
            if include_signatures:
                in_data.append(inp.script_sig)
            else:
                in_data.append("")
        out_data = []
        for outp in self.tx_out:
            out_data.append(str(outp.value))
            out_data.append(outp.script_pubkey)
        ser_dict = {
            "version": self.version,
            "tx_in": in_data,
            "tx_out": out_data,
            "lock_time": self.lock_time,
            "timestamp": self.timestamp
        }
        return json.dumps(ser_dict, sort_keys=True).encode("utf-8")

@dataclass
class BlockHeader:
    version: int
    prev_block_hash: str
    merkle_root: str
    timestamp: float
    bits: int
    nonce: int

    def serialize_header(self) -> bytes:
        d = {
            "version": self.version,
            "prev_block_hash": self.prev_block_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "bits": self.bits,
            "nonce": self.nonce
        }
        return json.dumps(d, sort_keys=True).encode('utf-8')

    def hash(self) -> str:
        return double_sha256(self.serialize_header()).hex()

@dataclass
class Block:
    header: BlockHeader
    transactions: List[Transaction] = field(default_factory=list)

    def block_hash(self) -> str:
        return self.header.hash()

@dataclass
class UTXO:
    tx_id: str
    out_idx: int
    amount: int
    script_pubkey: str

# -------------------------------------------------------------------------
# CRYPTO & SCRIPT
# -------------------------------------------------------------------------
def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def hash160(b: bytes) -> bytes:
    sha = hashlib.sha256(b).digest()
    rip = hashlib.new('ripemd160')
    rip.update(sha)
    return rip.digest()

def merkle_root(txs: List[Transaction]) -> str:
    if not txs:
        return "0"*64
    hashes = [double_sha256(tx.serialize(True)) for tx in txs]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        new_list = []
        for i in range(0, len(hashes), 2):
            new_list.append(double_sha256(hashes[i] + hashes[i+1]))
        hashes = new_list
    return hashes[0].hex()

def run_script(script_sig: str, script_pubkey: str, tx: Transaction, input_index: int) -> bool:
    """
    Very simplified P2PKH check:
      scriptSig = <sig> <pubkey>
      scriptPubKey = OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    """
    try:
        parts_sig = script_sig.split(" ")
        if len(parts_sig) != 2:
            return False
        sig_hex, pub_hex = parts_sig
        if pub_hex.startswith("0x"):
            pub_hex = pub_hex[2:]
        if sig_hex.startswith("0x"):
            sig_hex = sig_hex[2:]
        pub_bytes = bytes.fromhex(pub_hex)
        sig_bytes = bytes.fromhex(sig_hex)

        # check pubKeyHash
        pub_hash = hash160(pub_bytes).hex()
        parts_pub = script_pubkey.split(" ")
        if len(parts_pub) < 5:
            return False
        embedded_hash = parts_pub[2]
        if pub_hash != embedded_hash:
            return False

        # verify signature
        tx_copy = Transaction(
            version=tx.version,
            tx_in=[TxInput(i.tx_id, i.output_index, "") for i in tx.tx_in],
            tx_out=tx.tx_out,
            lock_time=tx.lock_time,
            timestamp=tx.timestamp
        )
        msg_hash = double_sha256(tx_copy.serialize(include_signatures=False))
        vk = ecdsa.VerifyingKey.from_string(pub_bytes, curve=ecdsa.SECP256k1)
        vk.verify(sig_bytes, msg_hash, hashfunc=hashlib.sha256)
        return True
    except Exception as e:
        logger.debug("Script error: %s", e)
        return False

# -------------------------------------------------------------------------
# BLOCKCHAIN
# -------------------------------------------------------------------------
class Blockchain:
    def __init__(self):
        self.blocks = {}
        self.tip = None
        self.height = 0
        self.current_difficulty = INITIAL_DIFFICULTY
        self.utxo_set = {}

        # Create a "genesis" block so there's some block at height 1
        # We won't prompt for an address here, but a real node might.
        genesis = self.create_genesis_block()
        self.add_block(genesis)

    def create_genesis_block(self) -> Block:
        coinbase_tx = Transaction(
            version=1,
            tx_in=[TxInput("0"*64, 0, "genesis")],
            tx_out=[TxOutput(COINBASE_VALUE, "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG")]
        )
        bh = BlockHeader(
            version=VERSION,
            prev_block_hash="0"*64,
            merkle_root=merkle_root([coinbase_tx]),
            timestamp=time.time(),
            bits=self.current_difficulty,
            nonce=0
        )
        return Block(bh, [coinbase_tx])

    def add_block(self, block: Block) -> bool:
        # skip real PoW checks if you want, or do them. We'll do a check for demonstration.
        target = self.current_difficulty
        block_hash_val = int(block.block_hash(), 16)
        if block_hash_val > target:
            logger.warning("Block fails PoW check: %x vs target %x", block_hash_val, target)
            return False

        # check merkle
        calc_root = merkle_root(block.transactions)
        if calc_root != block.header.merkle_root:
            logger.warning("Block has invalid merkle root.")
            return False

        # check parent
        if block.header.prev_block_hash not in self.blocks and block.header.prev_block_hash != "0"*64:
            logger.warning("Block parent unknown.")
            return False

        # validate all tx
        if not self.validate_block_txs(block):
            logger.warning("Block's transactions are invalid.")
            return False

        # accept
        bhash = block.block_hash()
        self.blocks[bhash] = block
        if self.tip is None or block.header.prev_block_hash == self.tip or block.header.prev_block_hash == "0"*64:
            self.tip = bhash
            self.height += 1
            self.update_utxo_with_block(block)
            # no real difficulty adjustment here in this minimal example
        logger.info("Accepted block %s at height %d", bhash, self.height)
        return True

    def validate_block_txs(self, block: Block) -> bool:
        if not block.transactions:
            return False
        coinbase = block.transactions[0]
        # check coinbase structure
        if len(coinbase.tx_in) != 1:
            return False
        # check reward
        total_out = sum(o.value for o in coinbase.tx_out)
        if total_out > self.block_reward():
            logger.warning("Coinbase pays too much: %d vs allowed %d", total_out, self.block_reward())
            return False

        # check other tx
        for t in block.transactions[1:]:
            if not self.validate_transaction(t):
                return False
        return True

    def validate_transaction(self, tx: Transaction) -> bool:
        input_sum = 0
        for idx, inp in enumerate(tx.tx_in):
            k = (inp.tx_id, inp.output_index)
            if k not in self.utxo_set:
                logger.debug("Tx references unknown/spent UTXO: %s", k)
                return False
            utxo = self.utxo_set[k]
            if not run_script(inp.script_sig, utxo.script_pubkey, tx, idx):
                logger.debug("Script check failed for input %d", idx)
                return False
            input_sum += utxo.amount
        output_sum = sum(o.value for o in tx.tx_out)
        if output_sum > input_sum:
            logger.debug("Tx outputs exceed inputs: %d > %d", output_sum, input_sum)
            return False
        return True

    def update_utxo_with_block(self, block: Block):
        for tx in block.transactions:
            txid = tx.tx_id()
            # spent
            for inp in tx.tx_in:
                k = (inp.tx_id, inp.output_index)
                if k in self.utxo_set:
                    del self.utxo_set[k]
            # add new
            for idx, outp in enumerate(tx.tx_out):
                self.utxo_set[(txid, idx)] = UTXO(txid, idx, outp.value, outp.script_pubkey)

    def block_reward(self) -> int:
        # halving
        halvings = self.height // HALVING_INTERVAL
        reward = COINBASE_VALUE >> halvings
        if reward < 1:
            reward = 1
        return reward

    def get_balance_for_address(self, address_hex: str) -> int:
        """
        Summation of all UTXOs whose scriptPubKey references that address.
        """
        total = 0
        for (tid, idx), utxo in self.utxo_set.items():
            # script: OP_DUP OP_HASH160 <address_hex> OP_EQUALVERIFY OP_CHECKSIG
            parts = utxo.script_pubkey.split(" ")
            if len(parts) >= 5:
                if parts[2] == address_hex:
                    total += utxo.amount
        return total

# -------------------------------------------------------------------------
# NODE
# -------------------------------------------------------------------------
class Node:
    def __init__(self, host: str, port: int, seed_node: Optional[str]):
        self.host = host
        self.port = port
        self.peers = set()
        if seed_node:
            h, p = seed_node.split(":")
            self.peers.add((h, int(p)))

        self.blockchain = Blockchain()
        self.mempool = {}  # txid -> Transaction

        # server socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.stop_event = threading.Event()

        # start threads
        threading.Thread(target=self.server_loop, daemon=True).start()
        threading.Thread(target=self.connect_loop, daemon=True).start()
        logger.info("Node started on %s:%d", self.host, self.port)

    def server_loop(self):
        while not self.stop_event.is_set():
            r, _, _ = select.select([self.sock], [], [], 1)
            if self.sock in r:
                conn, addr = self.sock.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def connect_loop(self):
        while not self.stop_event.is_set():
            for (ph, pp) in list(self.peers):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ph, pp))
                    msg = {
                        "type": "hello",
                        "host": self.host,
                        "port": self.port
                    }
                    self.send_message(s, msg)
                    s.close()
                except:
                    pass
            time.sleep(30)

    def handle_client(self, conn, addr):
        while not self.stop_event.is_set():
            header = self.recvall(conn, len(NETWORK_MAGIC))
            if not header:
                break
            if header != NETWORK_MAGIC:
                break
            length_data = self.recvall(conn, 4)
            if not length_data:
                break
            length = int.from_bytes(length_data, "big")
            data = self.recvall(conn, length)
            if not data:
                break
            try:
                msg = json.loads(data.decode("utf-8"))
                self.handle_message(msg, conn, addr)
            except Exception as e:
                logger.debug("Message parse error: %s", e)
                break
        conn.close()

    def recvall(self, conn, length):
        buf = b''
        while len(buf) < length:
            chunk = conn.recv(length - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def handle_message(self, msg, conn, addr):
        mtype = msg.get("type")
        if mtype == "hello":
            ph, pp = msg.get("host"), msg.get("port")
            logger.debug("Got hello from peer %s:%d", ph, pp)
            self.peers.add((ph, pp))
            self.send_peers(conn)
        elif mtype == "peers":
            for p in msg.get("peers", []):
                self.peers.add(tuple(p))
        elif mtype == "tx":
            tx_data = msg.get("tx")
            tx = self.tx_from_json(tx_data)
            txid = tx.tx_id()
            if txid not in self.mempool:
                if self.blockchain.validate_transaction(tx):
                    self.mempool[txid] = tx
                    logger.info("Added TX %s to mempool from %s", txid, addr)
                    self.broadcast(msg)
        elif mtype == "block":
            block_data = msg.get("block")
            blk = self.block_from_json(block_data)
            if self.blockchain.add_block(blk):
                logger.info("Accepted block from %s", addr)
                self.broadcast(msg)
        elif mtype == "get_balance":
            address = msg.get("address")
            bal = self.blockchain.get_balance_for_address(address)
            reply = {
                "type": "balance",
                "address": address,
                "balance": bal,
                "height": self.blockchain.height
            }
            self.send_message(conn, reply)
        elif mtype == "get_height":
            reply = {
                "type": "height",
                "height": self.blockchain.height
            }
            self.send_message(conn, reply)
        elif mtype == "faucet" and ENABLE_FAUCET:
            address = msg.get("address")
            self.create_faucet_block(address)
        else:
            logger.debug("Unknown message: %s", mtype)

    def send_peers(self, conn):
        m = {
            "type": "peers",
            "peers": list(self.peers)
        }
        self.send_message(conn, m)

    def broadcast(self, msg):
        for (ph, pp) in list(self.peers):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ph, pp))
                self.send_message(s, msg)
                s.close()
            except:
                pass

    def send_message(self, conn, msg):
        data = json.dumps(msg).encode("utf-8")
        length = len(data).to_bytes(4, "big")
        conn.sendall(NETWORK_MAGIC + length + data)

    def create_faucet_block(self, address: str):
        # Build a block paying FAUCET_REWARD to the given address (cheating, ignoring PoW).
        logger.info("Faucet request: awarding %d sat to address %s", FAUCET_REWARD, address)
        faucet_tx = Transaction(
            version=1,
            tx_in=[TxInput("0"*64, 0, f"faucet-{int(time.time())}")],
            tx_out=[TxOutput(FAUCET_REWARD, f"OP_DUP OP_HASH160 {address} OP_EQUALVERIFY OP_CHECKSIG")]
        )
        prev_hash = self.blockchain.tip or "0"*64
        mr = merkle_root([faucet_tx])
        bh = BlockHeader(
            version=VERSION,
            prev_block_hash=prev_hash,
            merkle_root=mr,
            timestamp=time.time(),
            bits=self.blockchain.current_difficulty,
            nonce=0
        )
        blk = Block(bh, [faucet_tx])

        # In real logic we'd do PoW. Here we skip.
        accepted = self.blockchain.add_block(blk)
        if accepted:
            # broadcast
            msg = {
                "type": "block",
                "block": self.block_to_json(blk)
            }
            self.broadcast(msg)
            logger.info("Faucet block accepted & broadcast.")
        else:
            logger.warning("Faucet block was not accepted.")

    def tx_from_json(self, tx_data):
        ins = tx_data["tx_in"]
        inputs = []
        for i in range(0, len(ins), 3):
            inputs.append(TxInput(ins[i], int(ins[i+1]), ins[i+2]))
        outs = tx_data["tx_out"]
        outputs = []
        for j in range(0, len(outs), 2):
            outputs.append(TxOutput(int(outs[j]), outs[j+1]))
        return Transaction(
            version=tx_data["version"],
            tx_in=inputs,
            tx_out=outputs,
            lock_time=tx_data["lock_time"],
            timestamp=tx_data["timestamp"]
        )

    def block_from_json(self, blk_data):
        h = blk_data["header"]
        hdr = BlockHeader(
            version=h["version"],
            prev_block_hash=h["prev_block_hash"],
            merkle_root=h["merkle_root"],
            timestamp=h["timestamp"],
            bits=h["bits"],
            nonce=h["nonce"]
        )
        txs = []
        for txd in blk_data["transactions"]:
            txs.append(self.tx_from_json(txd))
        return Block(hdr, txs)

    def block_to_json(self, blk: Block):
        hd = {
            "version": blk.header.version,
            "prev_block_hash": blk.header.prev_block_hash,
            "merkle_root": blk.header.merkle_root,
            "timestamp": blk.header.timestamp,
            "bits": blk.header.bits,
            "nonce": blk.header.nonce
        }
        txs = []
        for t in blk.transactions:
            txs.append(self.tx_to_json(t))
        return {
            "header": hd,
            "transactions": txs
        }

    def tx_to_json(self, tx: Transaction):
        j = {
            "version": tx.version,
            "tx_in": [],
            "tx_out": [],
            "lock_time": tx.lock_time,
            "timestamp": tx.timestamp
        }
        for inp in tx.tx_in:
            j["tx_in"].extend([inp.tx_id, inp.output_index, inp.script_sig])
        for outp in tx.tx_out:
            j["tx_out"].extend([outp.value, outp.script_pubkey])
        return j

def main():
    if len(sys.argv) < 2:
        print("Usage: python mattcoin_node.py <port> [seed_host:seed_port]")
        sys.exit(1)

    port = int(sys.argv[1])
    seed = sys.argv[2] if len(sys.argv) > 2 else None
    node = Node("0.0.0.0", port, seed)

    logger.info("Node running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        node.stop_event.set()
        logger.info("Node shutting down...")

if __name__ == "__main__":
    main()
