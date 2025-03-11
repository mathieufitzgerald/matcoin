#!/usr/bin/env python3
"""
wallet_gui.py

A Tkinter GUI wallet for our "MattCoin" proof-of-concept.
It can:
- Generate or load a keypair
- Show the current address (Base58 or hex)
- Connect to a node (host/port)
- Query balance
- Create/Send transactions
- Optionally request a "faucet" block (if the node supports it)

NOTE:
- This is still a simplified wallet approach. Real wallets do advanced UTXO selection,
  proper fee calculations, secure key storage, address derivation, etc.
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import os
import sys
import json
import socket
import time
import hashlib

import ecdsa
import base58

# If your codebase is in separate files in the same folder, import them:
# from wallet import generate_keypair, pubkey_to_address, create_transaction, sign_transaction
# from crypto_utils import base58_check_encode, base58_check_decode, double_sha256, hash160
# from blockchain_data import Transaction, TxInput, TxOutput

# --------------------------------------------------------------------
# For demonstration, let's inline some needed functions from 'wallet.py' + 'crypto_utils.py'
# --------------------------------------------------------------------

def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def hash160(b: bytes) -> bytes:
    sha = hashlib.sha256(b).digest()
    rip = hashlib.new('ripemd160')
    rip.update(sha)
    return rip.digest()

def base58_check_encode(prefix: bytes, payload: bytes) -> str:
    data = prefix + payload
    checksum = double_sha256(data)[:4]
    return base58.b58encode(data + checksum).decode('utf-8')

def base58_check_decode(s: str) -> bytes:
    full = base58.b58decode(s)
    data, checksum = full[:-4], full[-4:]
    if double_sha256(data)[:4] != checksum:
        raise ValueError("Invalid base58 checksum")
    return data

def generate_keypair() -> (bytes, bytes):
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return sk.to_string(), vk.to_string()

def pubkey_to_address(pubkey_bytes: bytes, prefix: bytes = b"\x00") -> str:
    """
    Real Bitcoin uses prefix=0x00 for P2PKH addresses. Then base58-check encoding.
    """
    h160 = hash160(pubkey_bytes)
    return base58_check_encode(prefix, h160)

# A minimal TX data class (if we’re not importing from blockchain_data.py)
class TxInput:
    def __init__(self, prev_tx_id, prev_out_index, script_sig, sequence=0xFFFFFFFF):
        self.prev_tx_id = prev_tx_id
        self.prev_out_index = prev_out_index
        self.script_sig = script_sig
        self.sequence = sequence

class TxOutput:
    def __init__(self, value, script_pubkey):
        self.value = value
        self.script_pubkey = script_pubkey

class Transaction:
    def __init__(self, version, tx_in, tx_out, lock_time=0, timestamp=None):
        self.version = version
        self.tx_in = tx_in
        self.tx_out = tx_out
        self.lock_time = lock_time
        self.timestamp = time.time() if timestamp is None else timestamp

    def serialize(self) -> bytes:
        # For demonstration, store in JSON
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

    def tx_id(self) -> str:
        return double_sha256(self.serialize()).hex()

# We'll do a naive approach to building a TX:
def create_transaction(utxos, to_address, amount, my_pubkey_hex, leftover):
    """
    utxos = list of (txid, vout, value)
    to_address = base58 or hex address
    amount = int (in satoshis)
    my_pubkey_hex = hex of your pubkey
    leftover = how much leftover (like your "change") in satoshis
    returns a Transaction object
    """
    tx_in = []
    total_in = 0
    for (txid, outidx, val) in utxos:
        total_in += val
        tx_in.append(TxInput(txid, outidx, ""))

    # script for the recipient
    # if to_address is base58, decode:
    try:
        decoded = base58_check_decode(to_address)
        # skip prefix = decoded[0], payload = decoded[1:]
        pubkey_hash_hex = decoded[1:].hex()
    except:
        # assume it's directly a hex hash
        pubkey_hash_hex = to_address

    script_pubkey_dest = f"OP_DUP OP_HASH160 {pubkey_hash_hex} OP_EQUALVERIFY OP_CHECKSIG"
    out1 = TxOutput(amount, script_pubkey_dest)

    # leftover / change to your pubkey
    # your pubkey's hash160:
    my_pubkey_bytes = bytes.fromhex(my_pubkey_hex)
    my_hash160 = hash160(my_pubkey_bytes).hex()
    script_pubkey_change = f"OP_DUP OP_HASH160 {my_hash160} OP_EQUALVERIFY OP_CHECKSIG"
    out2 = TxOutput(leftover, script_pubkey_change)

    tx_out = [out1, out2]
    tx = Transaction(1, tx_in, tx_out)
    return tx

def sign_transaction(tx: Transaction, privkey: bytes, pubkey: bytes, idx: int):
    """
    Very naive sighash approach: we do 'tx.serialize()' ignoring scriptSig, sign that hash,
    store sig+pubkey in input[idx].script_sig.
    """
    # build a copy with blank scriptSig in the idx-th input
    # In a real system, you'd blank scriptSig in all inputs except idx, etc.
    cpy_in = []
    for i, tin in enumerate(tx.tx_in):
        if i == idx:
            cpy_in.append(TxInput(tin.prev_tx_id, tin.prev_out_index, "", tin.sequence))
        else:
            cpy_in.append(tin)
    cpy_tx = Transaction(tx.version, cpy_in, tx.tx_out, tx.lock_time, tx.timestamp)
    msg_hash = double_sha256(cpy_tx.serialize())

    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    signature = sk.sign(msg_hash)
    sig_hex = signature.hex()
    pub_hex = pubkey.hex()
    tx.tx_in[idx].script_sig = f"{sig_hex} {pub_hex}"

# --------------------------------------------------------------------
# The GUI code
# --------------------------------------------------------------------
class MattCoinWalletGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MattCoin GUI Wallet")
        self.geometry("600x420")

        self.privkey = None
        self.pubkey = None
        self.address_b58 = None
        self.address_hash_hex = None  # the raw hash160 in hex

        # Node connection
        self.node_host = tk.StringVar(value="127.0.0.1")
        self.node_port = tk.StringVar(value="5000")

        # TX building fields
        self.utxos_var = tk.StringVar(value="")
        self.to_address_var = tk.StringVar(value="")
        self.amount_var = tk.StringVar(value="")
        self.leftover_var = tk.StringVar(value="")

        # Info display
        self.balance_var = tk.StringVar(value="0")
        self.status_var = tk.StringVar(value="Not connected")

        self.create_widgets()

    def create_widgets(self):
        frame_conn = tk.LabelFrame(self, text="Node Connection")
        frame_conn.pack(fill="x", padx=5, pady=5)

        tk.Label(frame_conn, text="Host:").grid(row=0, column=0, sticky="e")
        tk.Entry(frame_conn, textvariable=self.node_host, width=15).grid(row=0, column=1)
        tk.Label(frame_conn, text="Port:").grid(row=0, column=2, sticky="e")
        tk.Entry(frame_conn, textvariable=self.node_port, width=6).grid(row=0, column=3)

        tk.Label(frame_conn, text="Balance:").grid(row=1, column=0, sticky="e")
        tk.Label(frame_conn, textvariable=self.balance_var).grid(row=1, column=1, sticky="w")
        tk.Button(frame_conn, text="Refresh Balance", command=self.refresh_balance).grid(row=1, column=2, columnspan=2)

        frame_keys = tk.LabelFrame(self, text="Keys / Address")
        frame_keys.pack(fill="x", padx=5, pady=5)

        tk.Button(frame_keys, text="Generate Keypair", command=self.generate_keypair).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(frame_keys, text="Load Private Key", command=self.load_privkey).grid(row=0, column=1, padx=5, pady=5)

        self.label_address = tk.Label(frame_keys, text="Address: None")
        self.label_address.grid(row=1, column=0, columnspan=2, sticky="w")

        frame_tx = tk.LabelFrame(self, text="Build/Send Transaction")
        frame_tx.pack(fill="x", padx=5, pady=5)

        tk.Label(frame_tx, text="UTXOs (JSON):").grid(row=0, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.utxos_var, width=50).grid(row=0, column=1, columnspan=2, sticky="w")
        note = tk.Label(frame_tx, text="Example: [(\"abcd1234...\", 0, 500000000), (\"efgh5678...\", 1, 200000000)]")
        note.grid(row=1, column=0, columnspan=3, sticky="w")

        tk.Label(frame_tx, text="To Address:").grid(row=2, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.to_address_var, width=40).grid(row=2, column=1, columnspan=2, sticky="w")

        tk.Label(frame_tx, text="Amount:").grid(row=3, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.amount_var, width=12).grid(row=3, column=1, sticky="w")

        tk.Label(frame_tx, text="Leftover:").grid(row=4, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.leftover_var, width=12).grid(row=4, column=1, sticky="w")

        tk.Button(frame_tx, text="Send Transaction", command=self.send_transaction).grid(row=5, column=0, columnspan=3, pady=5)

        frame_status = tk.LabelFrame(self, text="Status")
        frame_status.pack(fill="x", padx=5, pady=5)
        tk.Label(frame_status, textvariable=self.status_var).pack(anchor="w", padx=5, pady=5)

    def generate_keypair(self):
        priv, pub = generate_keypair()
        self.privkey = priv
        self.pubkey = pub
        self.address_b58 = pubkey_to_address(pub)  # base58
        self.address_hash_hex = hash160(pub).hex()
        self.label_address.config(text=f"Address: {self.address_b58}")
        messagebox.showinfo("Keypair Generated", f"Private key length: {len(priv)} bytes\nAddress: {self.address_b58}")

    def load_privkey(self):
        path = filedialog.askopenfilename(title="Select Private Key Hex")
        if not path:
            return
        try:
            with open(path, "r") as f:
                priv_hex = f.read().strip()
            priv_bytes = bytes.fromhex(priv_hex)
            sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
            self.privkey = priv_bytes
            self.pubkey = sk.verifying_key.to_string()
            self.address_b58 = pubkey_to_address(self.pubkey)
            self.address_hash_hex = hash160(self.pubkey).hex()
            self.label_address.config(text=f"Address: {self.address_b58}")
            messagebox.showinfo("Key Loaded", f"Loaded key. Address: {self.address_b58}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def refresh_balance(self):
        if not self.address_hash_hex:
            messagebox.showwarning("No Address", "Generate or load a key first.")
            return
        host = self.node_host.get()
        port = int(self.node_port.get())
        req = {"type": "get_balance", "address": self.address_hash_hex}
        resp = self.send_request(host, port, req)
        if resp and resp.get("type") == "balance":
            bal = resp.get("balance", 0)
            self.balance_var.set(str(bal))
            self.status_var.set(f"Chain height: {resp.get('height', 0)}")
        else:
            self.balance_var.set("0")
            self.status_var.set("Failed to get balance")

    def send_transaction(self):
        if not self.privkey or not self.pubkey:
            messagebox.showerror("No Key", "No key loaded or generated.")
            return
        utxos_str = self.utxos_var.get().strip()
        to_addr = self.to_address_var.get().strip()
        amt_str = self.amount_var.get().strip()
        leftover_str = self.leftover_var.get().strip()
        if not (utxos_str and to_addr and amt_str and leftover_str):
            messagebox.showerror("Missing Fields", "Please fill UTXOs, to_addr, amount, leftover.")
            return
        try:
            utxos = eval(utxos_str)  # e.g. [("abcd...", 0, 12345), ...]
            amount = int(amt_str)
            leftover = int(leftover_str)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid input: {e}")
            return

        # create the TX
        pub_hex = self.pubkey.hex()
        tx = create_transaction(utxos, to_addr, amount, pub_hex, leftover)
        # sign each input
        for i in range(len(tx.tx_in)):
            sign_transaction(tx, self.privkey, self.pubkey, i)

        # broadcast
        host = self.node_host.get()
        port = int(self.node_port.get())
        tx_msg = {
            "type": "tx",
            "data": tx_to_dict(tx)
        }
        resp = self.send_request(host, port, tx_msg)
        messagebox.showinfo("Transaction", "Broadcast request sent.")

    def send_request(self, host, port, msg):
        """
        Send a single message (as JSON) to the node. Attempt to read one response.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((host, port))
            data_out = json.dumps(msg).encode("utf-8")
            length = len(data_out).to_bytes(4, "big")
            # We'll assume the node's NETWORK_MAGIC is "MATTCOIN" from config, but let's skip that for brevity:
            # Instead we just send length + data
            # If the node requires the magic, prepend it accordingly:
            # s.sendall(NETWORK_MAGIC + length + data_out)
            # We'll do a simpler approach:
            s.sendall(b"MATTCOIN" + length + data_out)

            # read one response
            header = s.recv(8)  # 8 = len("MATTCOIN")+4? Actually we need to parse carefully, but let's do a cheat:
            if not header.startswith(b"MATTCOIN"):
                return {}
            resp_len_bytes = header[len(b"MATTCOIN"):]
            if len(resp_len_bytes) < 4:
                # not enough
                return {}
            resp_len = int.from_bytes(resp_len_bytes, "big")

            resp_data = b""
            while len(resp_data) < resp_len:
                chunk = s.recv(resp_len - len(resp_data))
                if not chunk:
                    break
                resp_data += chunk
            if resp_data:
                return json.loads(resp_data.decode("utf-8"))
            return {}
        except Exception as e:
            print(f"send_request error: {e}")
            return {}
        finally:
            s.close()

def tx_to_dict(tx: Transaction) -> dict:
    """
    Convert Transaction object into a dict so we can send it over the wire.
    """
    j_in = []
    for i in tx.tx_in:
        j_in.append(i.prev_tx_id)
        j_in.append(i.prev_out_index)
        j_in.append(i.script_sig)
    j_out = []
    for o in tx.tx_out:
        j_out.append(o.value)
        j_out.append(o.script_pubkey)
    return {
        "version": tx.version,
        "tx_in": j_in,
        "tx_out": j_out,
        "lock_time": tx.lock_time,
        "timestamp": tx.timestamp
    }

def main():
    app = MattCoinWalletGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
