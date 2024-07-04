import argparse
import yaml
import asyncio
import signal
from ipv8.configuration import ConfigBuilder, default_bootstrap_defs
from ipv8.util import create_event_with_signals
from ipv8_service import IPv8
from algorithms import *
from algorithms.blockchain import BlockchainNode
from da_types import Blockchain
from flask_server import start_flask_app
import threading


def get_algorithm(name: str) -> Blockchain:
    algorithms = {
        'blockchain': BlockchainNode,
    }
    if name not in algorithms.keys():
        raise Exception(f'Cannot find selected algorithm with name {name}')
    return algorithms[name]

async def start_communities(node_id, connections, algorithm, use_localhost=True) -> None:
    event = create_event_with_signals()
    base_port = 8090
    connections_updated = [(x, base_port + x) for x in connections]
    node_port = base_port + node_id
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "medium", f"ec{node_id}.pem")
    builder.set_port(node_port)
    builder.add_overlay(
        "blockchain_community",
        "my peer",
        [],
        default_bootstrap_defs,
        {},
        [("started", node_id, connections_updated, event, use_localhost)],
    )
    ipv8_instance = IPv8(
        builder.finalize(), extra_communities={"blockchain_community": algorithm}
    )
    await ipv8_instance.start()

    return ipv8_instance

async def main():
    parser = argparse.ArgumentParser(
        prog="Blockchain",
        description="Code to execute blockchain.",
        epilog="Designed for A27 Fundamentals and Design of Blockchain-based Systems",
    )
    parser.add_argument("node_id", type=int, nargs="?", default=0)
    parser.add_argument("topology", type=str, nargs="?", default="topologies/blockchain.yaml")
    parser.add_argument("algorithm", type=str, nargs="?", default='blockchain')
    parser.add_argument("-docker", action='store_true')
    args = parser.parse_args()
    node_id = args.node_id

    alg = get_algorithm(args.algorithm)
    with open(args.topology, "r") as f:
        topology = yaml.safe_load(f)
        connections = topology[node_id]


    tasks = [start_communities(i, topology[i], alg, not args.docker) for i in range(4)]
    ipv8_instances = await asyncio.gather(*tasks)
    
    flask_thread = threading.Thread(target=start_flask_app, args=(alg, False, ), daemon=True)
    flask_thread.start()

    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass

    for ipv8_instance in ipv8_instances:
        await ipv8_instance.stop()

def shutdown():
    for task in asyncio.all_tasks():
        task.cancel()

if __name__ == "__main__":
    def handle_exit(sig, frame):
        print("Exiting...")
        shutdown()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, handle_exit)

        asyncio.run(main())

    except Exception as e:
        print(f"Error: {e}")
        shutdown()
