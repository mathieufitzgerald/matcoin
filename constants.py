#!/usr/bin/env python3
"""
constants.py

Constants for message types, etc.
"""

# Message types (just a few examples):
MSG_VERSION = "version"
MSG_VERACK = "verack"
MSG_GETPEERS = "getpeers"
MSG_PEERS = "peers"
MSG_INV = "inv"
MSG_GETDATA = "getdata"
MSG_BLOCK = "block"
MSG_TX = "tx"
MSG_GETBLOCKS = "getblocks"
MSG_GETHEADERS = "getheaders"
MSG_HEADERS = "headers"
MSG_PING = "ping"
MSG_PONG = "pong"
MSG_ALERT = "alert"

# Inventory types:
INVENTORY_ERROR = 0
INVENTORY_MSG_TX = 1
INVENTORY_MSG_BLOCK = 2
