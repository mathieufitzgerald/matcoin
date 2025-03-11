#!/usr/bin/env python3
"""
config.py

Global configuration parameters for our P2P node, chain, etc.
"""

# This is our "network magic" prefix for messages:
NETWORK_MAGIC = b"MATTCOIN"

# Protocol version & user agent string, just for demonstration.
PROTOCOL_VERSION = 70015
USER_AGENT = "/MattCoin:0.1/"

# Hardcoded seeds (host, port)
SEED_NODES = [
    # You can add more as needed
    ("127.0.0.1", 5000),
]

# For our toy PoW, let's set the difficulty fairly low so CPU mining is feasible.
# We'll require block_hash <= this target:
INITIAL_DIFFICULTY = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

# Our "genesis" coinbase message:
GENESIS_COINBASE_SCRIPT = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

# Initial block reward (50 MAT in satoshi-like units):
INITIAL_BLOCK_REWARD = 50_0000_0000

# Halving interval (like Bitcoin’s 210000, but you can lower for tests):
HALVING_INTERVAL = 210000

# For a real system, Bitcoin uses 10-min intervals and adjusts difficulty every 2016 blocks.
# We omit that complexity here or do it minimally if you want.

BLOCK_TARGET_TIME = 600  # 10 minutes for demonstration (not heavily used in this minimal code).
