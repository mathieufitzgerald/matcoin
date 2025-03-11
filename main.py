#!/usr/bin/env python3
"""
main.py

The main entry point. Usage:

  python main.py <port> [seed_host:seed_port]

Runs a full node:
- Creates Chain + Mempool
- Creates Node (p2p_node)
- Optionally starts a mining thread if you want
"""

import sys
import time
import logging

from chain_state import Chain, Mempool
from p2p_node import Node
from miner import mine_one_block
import threading

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
        seed_input = sys.argv[2]
        host_port = seed_input.split(":")
        seed = (host_port[0], int(host_port[1]))

    # build chain + mempool
    chain = Chain()
    mempool = Mempool()

    # create node
    node = Node("0.0.0.0", port, chain, mempool, seed)

    # Optional: start a background miner. Provide your address here:
    MINING_ADDRESS_HEX = "0000000000000000000000000000000000000000"

    def mining_loop():
        while not node.stop_event.is_set():
            mined = mine_one_block(chain, mempool, MINING_ADDRESS_HEX, node)
            if not mined:
                # no block found or we gave up
                time.sleep(2)
            else:
                # block found
                time.sleep(10)

    # Uncomment to enable mining:
    # threading.Thread(target=mining_loop, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        node.shutdown()

if __name__ == "__main__":
    main()
