#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import json
import os
import time
import hashlib

import ecdsa

NETWORK_MAGIC = b"MATTCoin"
TIMEOUT = 5  # 5-second socket timeout

# ------------------- Transaction Classes / Utilities -------------------------
class TxInput:
    def __init__(self, tx_id, output_index, script_sig):
        self.tx_id = tx_id
        self.output_index = output_index
        self.script_sig = script_sig

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
        self.timestamp = timestamp if timestamp else time.time()

    def serialize(self, include_signatures=True):
        inp_data = []
        for inp in self.tx_in:
            inp_data.append(inp.tx_id)
            inp_data.append(str(inp.output_index))
            if include_signatures:
                inp_data.append(inp.script_sig)
            else:
                inp_data.append("")
        out_data = []
        for o in self.tx_out:
            out_data.append(str(o.value))
            out_data.append(o.script_pubkey)

        d = {
            "version": self.version,
            "tx_in": inp_data,
            "tx_out": out_data,
            "lock_time": self.lock_time,
            "timestamp": self.timestamp
        }
        return json.dumps(d, sort_keys=True).encode("utf-8")

def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def hash160(b: bytes) -> bytes:
    sha = hashlib.sha256(b).digest()
    rip = hashlib.new("ripemd160")
    rip.update(sha)
    return rip.digest()

def generate_keypair():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return sk.to_string(), vk.to_string()

def pubkey_to_address(pubkey_bytes: bytes) -> str:
    return hash160(pubkey_bytes).hex()

def sign_transaction(tx: Transaction, privkey: bytes, pubkey: bytes, input_index: int):
    # Copy tx with blank scriptSig for the input we're signing
    tx_copy = Transaction(tx.version, [], tx.tx_out, tx.lock_time, tx.timestamp)
    for i, inp in enumerate(tx.tx_in):
        if i == input_index:
            tx_copy.tx_in.append(TxInput(inp.tx_id, inp.output_index, ""))
        else:
            tx_copy.tx_in.append(inp)

    msg = tx_copy.serialize(include_signatures=False)
    msg_hash = double_sha256(msg)
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    sig = sk.sign(msg_hash)
    sig_hex = sig.hex()
    pub_hex = pubkey.hex()
    tx.tx_in[input_index].script_sig = f"{sig_hex} {pub_hex}"

def tx_to_json(tx: Transaction):
    j = {
        "version": tx.version,
        "tx_in": [],
        "tx_out": [],
        "lock_time": tx.lock_time,
        "timestamp": tx.timestamp
    }
    for i in tx.tx_in:
        j["tx_in"].extend([i.tx_id, i.output_index, i.script_sig])
    for o in tx.tx_out:
        j["tx_out"].extend([o.value, o.script_pubkey])
    return j

# ------------------- Network / Node Communication ---------------------------
def send_message(host: str, port: int, msg) -> dict:
    """
    Send a message to the node and try to read one response (for queries).
    Returns the parsed JSON reply if any, or {} on error.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((host, port))
        data_out = json.dumps(msg).encode("utf-8")
        length = len(data_out).to_bytes(4, "big")
        s.sendall(NETWORK_MAGIC + length + data_out)

        # For certain messages (like get_balance, get_height), we expect a response:
        # We'll read exactly one message back, if any.
        header = recvall(s, len(NETWORK_MAGIC))
        if not header or header != NETWORK_MAGIC:
            return {}
        length_data = recvall(s, 4)
        if not length_data:
            return {}
        resp_len = int.from_bytes(length_data, "big")
        resp_bytes = recvall(s, resp_len)
        if not resp_bytes:
            return {}
        return json.loads(resp_bytes.decode("utf-8"))
    except:
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

def broadcast_tx(tx: Transaction, host: str, port: int):
    msg = {
        "type": "tx",
        "tx": tx_to_json(tx)
    }
    # no immediate response needed
    _ = send_message(host, port, msg)

def request_faucet(address: str, host: str, port: int):
    msg = {
        "type": "faucet",
        "address": address
    }
    _ = send_message(host, port, msg)

# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------
class MattCoinWalletGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MattCoin Wallet (No-Mining Node Edition)")
        self.geometry("600x420")

        self.privkey = None
        self.pubkey = None
        self.address = None

        self.node_host = tk.StringVar(value="127.0.0.1")
        self.node_port = tk.StringVar(value="5000")

        # TX Input fields
        self.txid_var = tk.StringVar()
        self.out_idx_var = tk.StringVar()
        self.value_var = tk.StringVar()
        self.dest_var = tk.StringVar()

        # Info display
        self.balance_var = tk.StringVar(value="0")
        self.height_var = tk.StringVar(value="N/A")
        self.sync_var = tk.StringVar(value="Unknown")

        self.create_widgets()

        # For a naive "sync check," we store last height:
        self.last_height = None

    def create_widgets(self):
        frame_node = tk.LabelFrame(self, text="Node Connection")
        frame_node.pack(fill="x", padx=5, pady=5)

        tk.Label(frame_node, text="Host:").grid(row=0, column=0, sticky="e")
        tk.Entry(frame_node, textvariable=self.node_host, width=15).grid(row=0, column=1)
        tk.Label(frame_node, text="Port:").grid(row=0, column=2, sticky="e")
        tk.Entry(frame_node, textvariable=self.node_port, width=6).grid(row=0, column=3)

        frame_keys = tk.LabelFrame(self, text="Keys")
        frame_keys.pack(fill="x", padx=5, pady=5)

        tk.Button(frame_keys, text="Generate Keypair", command=self.generate_keys).grid(row=0, column=0, padx=5)
        tk.Button(frame_keys, text="Load Private Key", command=self.load_key).grid(row=0, column=1, padx=5)

        self.label_addr = tk.Label(frame_keys, text="Address: N/A")
        self.label_addr.grid(row=1, column=0, columnspan=2, sticky="w")

        tk.Label(frame_keys, text="Balance:").grid(row=2, column=0, sticky="e")
        tk.Label(frame_keys, textvariable=self.balance_var).grid(row=2, column=1, sticky="w")

        tk.Label(frame_keys, text="Node Height:").grid(row=3, column=0, sticky="e")
        tk.Label(frame_keys, textvariable=self.height_var).grid(row=3, column=1, sticky="w")

        tk.Label(frame_keys, text="Sync Status:").grid(row=4, column=0, sticky="e")
        tk.Label(frame_keys, textvariable=self.sync_var).grid(row=4, column=1, sticky="w")

        tk.Button(frame_keys, text="Refresh Info", command=self.refresh_info).grid(row=5, column=0, columnspan=2, pady=5)

        frame_tx = tk.LabelFrame(self, text="Send Transaction")
        frame_tx.pack(fill="x", padx=5, pady=5)

        tk.Label(frame_tx, text="UTXO TxID:").grid(row=0, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.txid_var, width=45).grid(row=0, column=1, columnspan=2, sticky="w")

        tk.Label(frame_tx, text="Output Index:").grid(row=1, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.out_idx_var, width=4).grid(row=1, column=1, sticky="w")

        tk.Label(frame_tx, text="Value:").grid(row=2, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.value_var, width=10).grid(row=2, column=1, sticky="w")

        tk.Label(frame_tx, text="Destination:").grid(row=3, column=0, sticky="e")
        tk.Entry(frame_tx, textvariable=self.dest_var, width=45).grid(row=3, column=1, columnspan=2, sticky="w")

        tk.Button(frame_tx, text="Send TX", command=self.send_tx).grid(row=4, column=0, columnspan=3, pady=5)

        frame_faucet = tk.LabelFrame(self, text="Faucet (Optional)")
        frame_faucet.pack(fill="x", padx=5, pady=5)

        tk.Button(frame_faucet, text="Request 50 MAT", command=self.do_faucet).pack(padx=5, pady=5)

    # ----------------- Key Management ----------------------
    def generate_keys(self):
        priv, pub = generate_keypair()
        self.privkey = priv
        self.pubkey = pub
        self.address = pubkey_to_address(pub)
        self.label_addr.config(text=f"Address: {self.address}")
        messagebox.showinfo("Keys Generated", "Generated new keypair in memory.")

    def load_key(self):
        path = filedialog.askopenfilename(title="Select Private Key (hex)", filetypes=[("Text Files","*.txt"), ("All Files","*.*")])
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
            self.label_addr.config(text=f"Address: {self.address}")
            messagebox.showinfo("Key Loaded", f"Loaded private key from {os.path.basename(path)}.\nAddress: {self.address}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key: {e}")

    # ----------------- Node Interaction ----------------------
    def refresh_info(self):
        if not self.address:
            messagebox.showwarning("No address", "Load or generate a key first.")
            return
        host = self.node_host.get()
        port = int(self.node_port.get())

        # get_balance
        bal_resp = send_message(host, port, {"type":"get_balance", "address":self.address})
        if bal_resp.get("type") == "balance":
            balance = bal_resp.get("balance", 0)
            self.balance_var.set(str(balance))
            current_height = bal_resp.get("height", 0)
            self.height_var.set(str(current_height))
            # naive "sync check"
            if self.last_height is not None:
                if current_height == self.last_height:
                    self.sync_var.set("Synced (stable height)")
                else:
                    self.sync_var.set("Syncing (height changed)")
            self.last_height = current_height
        else:
            self.balance_var.set("0")
            self.sync_var.set("Unknown")
            self.height_var.set("N/A")

        # also can do get_height if you want it separate:
        # h_resp = send_message(host, port, {"type":"get_height"})

    def send_tx(self):
        if not self.privkey or not self.pubkey:
            messagebox.showerror("No Key", "No private key loaded or generated.")
            return
        txid = self.txid_var.get().strip()
        out_idx = self.out_idx_var.get().strip()
        val = self.value_var.get().strip()
        dest = self.dest_var.get().strip()
        if not txid or not out_idx.isdigit() or not val.isdigit() or not dest:
            messagebox.showerror("Invalid TX Data", "Please fill in the fields properly.")
            return
        out_idx = int(out_idx)
        val = int(val)

        inp = TxInput(txid, out_idx, "")
        outp = TxOutput(val, f"OP_DUP OP_HASH160 {dest} OP_EQUALVERIFY OP_CHECKSIG")
        tx = Transaction(1, [inp], [outp])
        sign_transaction(tx, self.privkey, self.pubkey, 0)

        host = self.node_host.get()
        port = int(self.node_port.get())
        broadcast_tx(tx, host, port)
        messagebox.showinfo("TX Sent", "Transaction broadcast to the node.")

    def do_faucet(self):
        if not self.address:
            messagebox.showwarning("No address", "Need a wallet address first.")
            return
        host = self.node_host.get()
        port = int(self.node_port.get())
        request_faucet(self.address, host, port)
        messagebox.showinfo("Faucet", "Requested 50 MAT from node (if faucet is enabled).")

def main():
    app = MattCoinWalletGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
