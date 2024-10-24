from Peer import Peer
from typing import Iterable, Set

PEER_DB_FILE = "peers.csv"


def store_peer(peer: Peer, existing_peers: Iterable[Peer] = None):
    # append to file
    if existing_peers is None:
        existing_peers = load_peers()
    
    if not peer in existing_peers:
        with open(PEER_DB_FILE, 'a') as f:
            f.write(f"{str(peer.host)},{peer.port}\n")
    
def load_peers() -> Set[Peer]:
    # read from file
    try:
        with open(PEER_DB_FILE, 'r') as f:
            peers = set()
            f.readline()  # Skip the header line
            for line in f.readlines():
                host, port = line.strip().split(',')
                peers.add(Peer(host, int(port)))
        return peers
    except FileNotFoundError:
        return set()
