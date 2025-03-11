#!/usr/bin/env python3
"""
main.py

The main entry point for the MattCoin node.
Usage:
  python main.py <port> [seed_host:seed_port]

Runs a full node:
- Creates chain + mempool
- Launches Node (p2p_node.py)
- Optionally you can enable a mining thread here or you can run miner.py separately.
"""

import sys
import time
import logging
import threading

from chain_state import Chain, Mempool
from p2p_node import Node
from miner import mine_one_block
from config import INITIAL_BLOCK_REWARD

def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s] %(levelname)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    if len(sys.argv) < 2:
        print("Usage: python main.py <port> [seedhost:seedport]")
        sys.exit(1)

    port = int(sys.argv[1])
    seed = None
    if len(sys.argv) > 2:
        parts = sys.argv[2].split(":")
        seed = (parts[0], int(parts[1]))

    chain = Chain()
    mempool = Mempool()
    node = Node("0.0.0.0", port, chain, mempool, seed)

    # Optional: you can do an internal mining loop:
    # EXAMPLE: We mine to a dummy address:
    # MINING_HASH_HEX = "0000000000000000000000000000000000000000"
    # def mining_thread():
    #     while not node.stop_event.is_set():
    #         mined = mine_one_block(chain, mempool, MINING_HASH_HEX, node)
    #         if mined:
    #             time.sleep(5)
    #         else:
    #             time.sleep(2)
    # threading.Thread(target=mining_thread, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        node.shutdown()

if __name__ == "__main__":
    main()
