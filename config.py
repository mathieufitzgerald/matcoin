#!/usr/bin/env python3
"""
config.py

Global configuration parameters and toggles.
"""

#####################
# Network / P2P
#####################

# Magic bytes for identifying messages on our network:
NETWORK_MAGIC = b"MATCOIN"

# Protocol version:
PROTOCOL_VERSION = 70015

# User agent string (like /Satoshi:0.1/):
USER_AGENT = "/MatCoin:0.1/"

# Default port for mainnet (just an example):
DEFAULT_PORT = 5005

# Hardcoded seed nodes (host, port):
SEED_NODES = [
    ("127.0.0.1", 5005),
    # Add more seeds for real usage
]

#####################
# Blockchain
#####################

# "PoW" difficulty target for demonstration. In real Bitcoin this is adjusted every block set.
# We'll keep it fairly easy so CPU mining won't take centuries:
INITIAL_DIFFICULTY = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

# Halving interval for block rewards:
HALVING_INTERVAL = 210000  # Real Bitcoin uses 210,000 blocks

# Target time for each block (seconds). Real Bitcoin uses ~10 minutes = 600s
BLOCK_TARGET_TIME = 120  # 2 minutes, for demonstration

# Adjust difficulty every X blocks:
DIFFICULTY_ADJUST_INTERVAL = 2016  # Real Bitcoin = 2016

# Max block size (very simplified):
MAX_BLOCK_SIZE = 1_000_000  # 1 MB

# Genesis block parameters (we'll define a message or script in the coinbase):
GENESIS_COINBASE_SCRIPT = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

#####################
# Economics
#####################

# Initial block reward:
INITIAL_BLOCK_REWARD = 50_0000_0000  # 50 MAT in "satoshi" units if 1 MAT=1e8

#####################
# Mempool / Fees
#####################

# Default minimum fee rate in sat/KB (very naive):
MIN_TX_FEE_RATE = 1000

# Mempool max size in bytes:
MAX_MEMPOOL_SIZE = 300_000_000  # 300 MB, demonstration
