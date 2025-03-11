#!/usr/bin/env python3
"""
wallet_gui.py

A Tkinter GUI wallet that:
- Generates or loads a private key
- Displays an address
- Connects to node (host:port)
- Queries balance
- Builds/sends transactions

Run: python wallet_gui.py
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import os
import json
import socket
import time

import ecdsa
from wallet import (
    generate_keypair, pubkey_to_address, sign_transaction, create_transaction
)
from blockchain_data import TxInput, TxOutput, Transaction
from crypto_utils import double_sha256, base58_check_decode
from constants import MSG_GET_BALANCE, MSG_BALANCE, MSG_TX
from config import NETWORK_MAGIC

def send_request(host: str, port: int, obj: dict):
    """
    Send a single message with format: [NETWORK_MAGIC][4-byte length][JSON]
    Then read exactly one response in the same format.
    Returns the parsed dict or {} on error.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((host, port))
        data = json.dumps(obj).encode('utf-8')
        length = len(data).to_bytes(4, 'big')
        s.sendall(NETWORK_MAGIC + length + data)

        # read response
        header = recvall(s, len(NETWORK_MAGIC))
        if header != NETWORK_MAGIC:
            return {}
        length_bytes = recvall(s, 4)
        if not length_bytes:
            return {}
        resp_len = int.from_bytes(length_bytes, 'big')
        resp_data = recvall(s, resp_len)
        if not resp_data:
            return {}
        return json.loads(resp_data.decode('utf-8'))
    except Exception as e:
        print("send_request error:", e)
        return {}
    finally:
        s.close()

def recvall(conn, length):
    buf = b''
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

class MattCoinWalletGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MattCoin GUI Wallet")
        self.geometry("600x420")

        self.privkey = None
        self.pubkey = None
        self.address = None  # base58
        self.hash160_hex = None

        self.node_host = tk.StringVar(value="127.0.0.1")
        self.node_port = tk.StringVar(value="5000")

        self.balance_var = tk.StringVar(value="0")

        # TX building
        self.utxos_var = tk.StringVar(value="")
        self.to_addr_var = tk.StringVar(value="")
        self.amount_var = tk.StringVar(value="0")
        self.change_addr_var = tk.StringVar(value="")
        self.leftover_var = tk.StringVar(value="0")

        self.create_widgets()

    def create_widgets(self):
        frame_conn = tk.LabelFrame(self, text="Node Connection")
        frame_conn.pack(fill="x", padx=5, pady=5)

        tk.Label(frame_conn, text="Host:").grid(row=0, column=0, sticky="e")
        tk.Entry(frame_conn, textvariable=self.node_host, width=12).grid(row=0, column=1)
        tk.Label(frame_conn, text="Port:").grid(row=0, column=2, sticky="e")
        tk.Entry(frame_conn, textvariable=self.node_port, width=6).grid(row=0, column=3)

        tk.Label(frame_conn, text="Balance:").grid(row=1, column=0, sticky="e")
        tk.Label(frame_conn, textvariable=self.balance_var).grid(row=1, column=1, sticky="w")
        tk.Button(frame_conn, text="Refresh Balance", command=self.refresh_balance).grid(row=1, column=2, columnspan=2)

        frame_keys = tk.LabelFrame(self, text="Keys / Address")
        frame_keys.pack(fill="x", padx=5, pady=5)

        tk.Button(frame_keys, text="Generate Keypair", command=self.generate_key).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(frame_keys, text="Load Private Key", command=self.load_key).grid(row=0, column=1, padx=5, pady=5)

        self.label_addr = tk.Label(frame_keys, text="Address: None")
        self.label_addr.grid(row=1, column=0, columnspan=2, sticky="w")

        frame_tx = tk.LabelFrame(self, text="Build/Send TX")
        frame_tx.pack(fill="x", padx=5, pady=5)

        tk.Label(frame_tx, text="UTXOs (Python list):").grid(row=0, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.utxos_var, width=40).grid(row=0, column=1, columnspan=2, sticky="w")

        tk.Label(frame_tx, text="To Address:").grid(row=1, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.to_addr_var, width=40).grid(row=1, column=1, columnspan=2, sticky="w")

        tk.Label(frame_tx, text="Amount:").grid(row=2, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.amount_var, width=12).grid(row=2, column=1, sticky="w")

        tk.Label(frame_tx, text="Change Addr:").grid(row=3, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.change_addr_var, width=40).grid(row=3, column=1, columnspan=2, sticky="w")

        tk.Label(frame_tx, text="Leftover:").grid(row=4, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.leftover_var, width=12).grid(row=4, column=1, sticky="w")

        tk.Button(frame_tx, text="Send TX", command=self.build_and_send_tx).grid(row=5, column=0, columnspan=3, pady=5)

    def generate_key(self):
        priv, pub = generate_keypair()
        self.privkey = priv
        self.pubkey = pub
        self.address = pubkey_to_address(pub)  # base58
        self.hash160_hex = hash160(pub).hex()
        self.label_addr.config(text=f"Address: {self.address}")
        messagebox.showinfo("Generated Key", f"PrivKey length={len(priv)}, Address={self.address}")

    def load_key(self):
        path = filedialog.askopenfilename(title="Private Key (hex)")
        if not path:
            return
        try:
            with open(path, "r") as f:
                priv_hex = f.read().strip()
            priv_bytes = bytes.fromhex(priv_hex)
            sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
            self.privkey = priv_bytes
            self.pubkey = sk.verifying_key.to_string()
            self.address = pubkey_to_address(self.pubkey)
            self.hash160_hex = hash160(self.pubkey).hex()
            self.label_addr.config(text=f"Address: {self.address}")
            messagebox.showinfo("Key Loaded", f"Address={self.address}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def refresh_balance(self):
        if not self.hash160_hex:
            messagebox.showwarning("No key", "Generate or load a key first.")
            return
        host = self.node_host.get()
        port = int(self.node_port.get())
        msg = {
            "type": "get_balance",
            "address": self.hash160_hex
        }
        resp = send_request(host, port, msg)
        if resp and resp.get("type") == "balance":
            self.balance_var.set(str(resp.get("balance", 0)))
        else:
            self.balance_var.set("0")

    def build_and_send_tx(self):
        if not self.privkey or not self.pubkey:
            messagebox.showerror("No Key", "Load or generate a key first.")
            return
        # parse utxos
        try:
            utxos = eval(self.utxos_var.get())
            amount = int(self.amount_var.get())
            leftover = int(self.leftover_var.get())
            to_addr = self.to_addr_var.get()
            ch_addr = self.change_addr_var.get()
        except Exception as e:
            messagebox.showerror("Error", f"Invalid input: {e}")
            return

        tx = create_transaction(utxos, to_addr, amount, ch_addr, leftover)
        # sign each input
        for i in range(len(tx.tx_in)):
            sign_transaction(tx, self.privkey, self.pubkey, i)

        # broadcast
        host = self.node_host.get()
        port = int(self.node_port.get())
        tx_dict = tx_to_dict(tx)
        msg = {
            "type": "tx",
            "data": tx_dict
        }
        resp = send_request(host, port, msg)
        messagebox.showinfo("Broadcast", "Transaction broadcast request sent.")

def tx_to_dict(tx: Transaction):
    j_in = []
    for i in tx.tx_in:
        j_in.extend([i.prev_tx_id, i.prev_out_index, i.script_sig])
    j_out = []
    for o in tx.tx_out:
        j_out.extend([o.value, o.script_pubkey])
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
