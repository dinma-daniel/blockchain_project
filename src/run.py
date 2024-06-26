import argparse
import yaml
from asyncio import run, all_tasks
from ipv8.configuration import ConfigBuilder, default_bootstrap_defs
from ipv8.util import create_event_with_signals, run_forever
from ipv8_service import IPv8
from algorithms import *
from algorithms.blockchain import BlockchainNode
from da_types import Blockchain


def get_algorithm(name: str) -> Blockchain:
    algorithms = {
        # 'echo': EchoAlgorithm,
        # 'election': RingElection,
        'blockchain': BlockchainNode,
    }
    if name not in algorithms.keys():
        raise Exception(f'Cannot find select algorithm with name {name}')
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
    await event.wait()
    await ipv8_instance.stop()

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
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        run(main())
    except Exception as e:
        print(f"Error: {e}")
        for task in all_tasks():
            task.cancel()
