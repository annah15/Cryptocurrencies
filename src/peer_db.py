from Peer import Peer
from typing import Iterable, Set

PEER_DB_FILE = "peers.csv"


def store_peer(peer: Peer, existing_peers: Iterable[Peer] = None):
    # append to file
    with open(PEER_DB_FILE, 'a') as f:
        f.write(f"{peer.host},{peer.port}\n")


def load_peers() -> Set[Peer]:
    # read from file
    with open(PEER_DB_FILE, 'r') as f:
        peers = set()
        for line in f:
            host, port = line.strip().split(',')
            peers.add(Peer(host, int(port)))
    return peers
