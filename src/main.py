from Peer import Peer
import constants as const
from message.msgexceptions import *
from jcs import canonicalize

import mempool
import objects
import peer_db

import asyncio
import ipaddress
import json
import random
import re
import sqlite3
import sys

PEERS = set()
CONNECTIONS = dict()
BACKGROUND_TASKS = set()
BLOCK_VERIFY_TASKS = dict()
BLOCK_WAIT_LOCK = None
TX_WAIT_LOCK = None
MEMPOOL = mempool.Mempool(const.GENESIS_BLOCK_ID, {})
LISTEN_CFG = {
        "address": const.ADDRESS,
        "port": const.PORT
}
MAX_CONNECTIONS = 10

# Add peer to your list of peers
def add_peer(peer):
    pass # TODO

# Add connection if not already open
def add_connection(peer, queue):
    pass # TODO

# Delete connection
def del_connection(peer):
    pass # TODO

# Make msg objects
def mk_error_msg(error_str, error_name):
    return {
        "type": "error",
        "name": error_name,
        "msg": error_str
    }

def mk_hello_msg():
    return {
        "type": "hello",
        "version": const.VERSION,
        "agent": const.AGENT
    }

def mk_getpeers_msg():
    return {
        "type": "getpeers"
    }

def mk_peers_msg():
    return {
        "type": "peers",
        "peers": [str(peer) for peer in list(PEERS)[-30:]]
    }

def mk_getobject_msg(objid):
    pass # TODO

def mk_object_msg(obj_dict):
    pass # TODO

def mk_ihaveobject_msg(objid):
    pass # TODO

def mk_chaintip_msg(blockid):
    pass # TODO

def mk_mempool_msg(txids):
    pass # TODO

def mk_getchaintip_msg():
    pass # TODO

def mk_getmempool_msg():
    pass # TODO

# parses a message as json. returns decoded message
def parse_msg(msg_str):
    try:
        msg_dict = json.loads(msg_str)
    except json.JSONDecodeError:
        raise MalformedMsgException("Invalid JSON format")
    return msg_dict

# Send data over the network as a message
async def write_msg(writer, msg_dict):
    msg = json.dumps(msg_dict, default=canonicalize) + "\n"
    writer.write(msg.encode())
    await writer.drain()

# Check if message contains no invalid keys,
# raises a MalformedMsgException
def validate_allowed_keys(msg_dict, allowed_keys, msg_type):
    for key in msg_dict.keys():
        if key not in allowed_keys:
            raise MalformedMsgException(f"Invalid key {key} in {msg_type} message")


# Validate the hello message
# raises an exception
def validate_hello_msg(msg_dict):
    keys = {'type', 'version', 'agent'}

    # Check for invalid keys
    validate_allowed_keys(msg_dict, keys, 'hello')

    # Check for missing required keys
    for key in keys:
        if key not in msg_dict:
            raise MalformedMsgException(f"Missing required key {key} in hello message")

    # Validate version format (example: "1.10.x")
    version_pattern = re.compile(r'^0\.10\.\d$')
    if not version_pattern.match(msg_dict['version']):
        raise MalformedMsgException(f"Invalid version format: {msg_dict['version']}")

    # Validate agent key
    agent = msg_dict['agent']
    if len(agent) > 128:
        raise MalformedMsgException("Agent key is longer than 128 characters")
    if not all(c.isprintable() for c in agent):
        raise MalformedMsgException("Agent key contains non-printable characters")

# returns true iff host_str is a valid hostname
def validate_hostname(host_str):
    pass # TODO

# returns true iff host_str is a valid ipv4 address
def validate_ipv4addr(host_str):
    pass # TODO

# returns true iff peer_str is a valid peer address
def validate_peer_str(peer_str):
    pass # TODO

# raise an exception if not valid
def validate_peers_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_getpeers_msg(msg_dict):
    validate_allowed_keys(msg_dict, {'type'}, 'getpeers')

# raise an exception if not valid
def validate_getchaintip_msg(msg_dict):
    validate_allowed_keys(msg_dict, {'type'}, 'getchaintip')

# raise an exception if not valid
def validate_getmempool_msg(msg_dict):
    validate_allowed_keys(msg_dict, {'type'}, 'getmempool')

# raise an exception if not valid
def validate_error_msg(msg_dict):
    keys = {'type', 'name', 'msg'}
    validate_allowed_keys(msg_dict, keys, 'error')

    for key in keys:
        if key not in msg_dict:
            raise MalformedMsgException(f"Missing required key {key} in error message")
    
    if not msg_dict['name'] in {'INVALID_FORMAT', 'INVALID_HANDSHAKE','INVALID_TX_CONSERVATION', 'INVALID_TX_SIGNATURE', 'INVALID_TX_OUTPOINT', 'INVALID_BLOCK_POW', 'INVALID_BLOCK_TIMESTAMP', 'INVALID_BLOCK_COINBASE', 'INVALID_GENESIS', 'UNKNOWN_OBJECT', 'UNFINDABLE_OBJECT', 'INVALID_ANCESTRY' }:
        raise MalformedMsgException("Invalid error name")
    
# raise an exception if not valid
def validate_ihaveobject_msg(msg_dict):
    keys = {'type', 'objectid'}
    validate_allowed_keys(msg_dict, keys, 'ihaveobject')

    if 'objectid' not in msg_dict:
        raise MalformedMsgException(f"Missing required key objectid in ihaveobject message")

# raise an exception if not valid
def validate_getobject_msg(msg_dict):
    keys = {'type', 'objectid'}
    validate_allowed_keys(msg_dict, keys, 'getobject')

    if 'objectid' not in msg_dict:
        raise MalformedMsgException(f"Missing required key objectid in getobject message")

# raise an exception if not valid
def validate_object_msg(msg_dict):
    keys = {'type', 'object'}
    validate_allowed_keys(msg_dict, keys, 'object')

    if 'object' not in msg_dict:
        raise MalformedMsgException(f"Missing required key object in object message")

# raise an exception if not valid
def validate_chaintip_msg(msg_dict):
    keys = {'type', 'blockid'}
    validate_allowed_keys(msg_dict, keys, 'chaintip')

    if 'blockid' not in msg_dict:
        raise MalformedMsgException(f"Missing required key blockid in chaintip message")
    
# raise an exception if not valid
def validate_mempool_msg(msg_dict):
    keys = {'type', 'txids'}
    validate_allowed_keys(msg_dict, keys, 'mempool')

    if 'txids' not in msg_dict:
        raise MalformedMsgException(f"Missing required key txids in mempool message")

    
        
def validate_msg(msg_dict):
    msg_type = msg_dict['type']
    if msg_type == 'hello':
        validate_hello_msg(msg_dict)
    elif msg_type == 'getpeers':
        validate_getpeers_msg(msg_dict)
    elif msg_type == 'peers':
        validate_peers_msg(msg_dict)
    elif msg_type == 'getchaintip':
        validate_getchaintip_msg(msg_dict)
    elif msg_type == 'getmempool':
        validate_getmempool_msg(msg_dict)
    elif msg_type == 'error':
        validate_error_msg(msg_dict)
    elif msg_type == 'ihaveobject':
        validate_ihaveobject_msg(msg_dict)
    elif msg_type == 'getobject':
        validate_getobject_msg(msg_dict)
    elif msg_type == 'object':
        validate_object_msg(msg_dict)
    elif msg_type == 'chaintip':
        validate_chaintip_msg(msg_dict)
    elif msg_type == 'mempool':
        validate_mempool_msg(msg_dict)
    else:
        raise UnsupportedMsgException(f"Unsupported message type {msg_type}")


def handle_peers_msg(msg_dict):
    peers = msg_dict['peers']
    for peer_str in peers:
        host, port = peer_str.split(':')
        peer = Peer(host, int(port))
        if peer not in PEERS:
            add_peer(peer)
            peer_db.store_peer(peer)


def handle_error_msg(msg_dict, peer_self):
    pass # TODO


async def handle_ihaveobject_msg(msg_dict, writer):
    pass # TODO


async def handle_getobject_msg(msg_dict, writer):
    pass # TODO

# return a list of transactions that tx_dict references
def gather_previous_txs(db_cur, tx_dict):
    # coinbase transaction
    if 'height' in tx_dict:
        return {}

    pass # TODO

# get the block, the current utxo and block height
def get_block_utxo_height(blockid):
    # TODO
    block = ''
    utxo = ''
    height = ''
    return (block, utxo, height)

# get all transactions as a dict txid -> tx from a list of ids
def get_block_txs(txids):
    pass # TODO


# Stores for a block its utxoset and height
def store_block_utxo_height(block, utxo, height: int):
    pass # TODO

# runs a task to verify a block
# raises blockverifyexception
async def verify_block_task(block_dict):
    pass # TODO

# adds a block verify task to queue and starting it
def add_verify_block_task(objid, block, queue):
    pass # TODO

# abort a block verify task
async def del_verify_block_task(task, objid):
    pass # TODO

# what to do when an object message arrives
async def handle_object_msg(msg_dict, peer_self, writer):
    pass # TODO


# returns the chaintip blockid
def get_chaintip_blockid():
    pass # TODO


async def handle_getchaintip_msg(msg_dict, writer):
    pass # TODO


async def handle_getmempool_msg(msg_dict, writer):
    pass # TODO


async def handle_chaintip_msg(msg_dict):
    pass # TODO


async def handle_mempool_msg(msg_dict):
    pass # TODO

# Helper function
async def handle_queue_msg(msg_dict, writer):
    pass # TODO

# how to handle a connection
async def handle_connection(reader, writer):
    read_task = None
    queue_task = None

    buffer = ""

    peer = None
    queue = asyncio.Queue()
    try:
        peer = writer.get_extra_info('peername')
        if not peer:
            raise Exception("Failed to get peername!")

        print("New connection with {}".format(peer))
    except Exception as e:
        print(str(e))
        try:
            writer.close()
        except:
            pass
        return

    try:
        # Send initial messages
        hello_msg = mk_hello_msg()
        await write_msg(writer, hello_msg)

        # Complete handshake
        if read_task is None:
                read_task = asyncio.create_task(reader.readline())
            
        # wait for hello message
        first_msg = await asyncio.wait_for(read_task, timeout=const.HELLO_MSG_TIMEOUT)
        
        buffer += first_msg.decode()
        # split the first message from the buffer
        msg, buffer = buffer.split("\n", 1)
        msg.canonicalize()
        msg_dict = parse_msg(msg)

        # Check if the message is a hello message
        if msg_dict['type'] != 'hello':
            raise MessageException("Invalid handshake")
            
        # Validate the hello message
        validate_hello_msg(msg_dict, {'type', 'version', 'agent'}, 'hello')

        # Get list of peers
        peers_msg = mk_peers_msg()
        await write_msg(writer, peers_msg)
  

        msg_str = None
        while True:
            if read_task is None:
                read_task = asyncio.create_task(reader.readline())
            if queue_task is None:
                queue_task = asyncio.create_task(queue.get())

            # wait for network or queue messages
            done, pending = await asyncio.wait([read_task, queue_task],
                    return_when = asyncio.FIRST_COMPLETED)
            if read_task in done:
                msg_str = read_task.result()
                read_task = None
            # handle queue messages
            if queue_task in done:
                queue_msg = queue_task.result()
                queue_task = None
                await handle_queue_msg(queue_msg, writer)
                queue.task_done()

            # if no message was received over the network continue
            if read_task is not None:
                continue

            print(f"Received: {msg_str}")
            # save the decoded message to a buffer
            buffer += msg_str.decode()
            while "\n" in buffer:
                # split the first message from the buffer
                msg, buffer = buffer.split("\n", 1)
                # parse the message, validate it and handle it
                try:
                    msg.canonicalize()
                    msg_dict = parse_msg(msg)
                    validate_msg(msg_dict)
                except MessageException as e:
                    await write_msg(writer, mk_error_msg("INVALID_FORMAT", str(e)))
                    continue
                except KeyError as e:
                    await write_msg(writer, mk_error_msg("INVALID_FORMAT", str(e)))
                    continue
                
                msg_type = msg_dict['type']
                if msg_type == 'get_peers':
                    peers_msg = mk_peers_msg()
                    await write_msg(writer, peers_msg)
                elif msg_type == 'peers':
                    await handle_peers_msg(msg_dict)
                elif msg_type == 'getchaintip':
                    await handle_getchaintip_msg(msg_dict)
                elif msg_type == 'getmempool':
                    await handle_getmempool_msg(msg_dict)
                elif msg_type == 'error':
                    await handle_error_msg(msg_dict)
                elif msg_type == 'ihaveobject':
                    await handle_ihaveobject_msg(msg_dict)
                elif msg_type == 'getobject':
                    await handle_getobject_msg(msg_dict)
                elif msg_type == 'object':
                    await handle_object_msg(msg_dict)
                elif msg_type == 'chaintip':
                    await handle_chaintip_msg(msg_dict)
                elif msg_type == 'mempool':
                    await handle_mempool_msg(msg_dict)
                else:
                    raise UnsupportedMsgException(f"Unsupported message type {msg_type}")


            # for now, close connection
            raise MessageException("closing connection")

    except asyncio.exceptions.TimeoutError:
        print("{}: Timeout".format(peer))
        try:
            await write_msg(writer, mk_error_msg("Timeout"))
        except:
            pass
    except MessageException as e:
        print("{}: {}".format(peer, str(e)))
        try:
            await write_msg(writer, mk_error_msg(e.NETWORK_ERROR_MESSAGE))
        except:
            pass
    except Exception as e:
        print("{}: {}".format(peer, str(e)))
    finally:
        print("Closing connection with {}".format(peer))
        writer.close()
        del_connection(peer)
        if read_task is not None and not read_task.done():
            read_task.cancel()
        if queue_task is not None and not queue_task.done():
            queue_task.cancel()


async def connect_to_node(peer: Peer):
    try:
        reader, writer = await asyncio.open_connection(peer.host, peer.port,
                limit=const.RECV_BUFFER_LIMIT)
    except Exception as e:
        print(str(e))
        return

    await handle_connection(reader, writer)


async def listen():
    server = await asyncio.start_server(handle_connection, LISTEN_CFG['address'],
            LISTEN_CFG['port'], limit=const.RECV_BUFFER_LIMIT)

    print("Listening on {}:{}".format(LISTEN_CFG['address'], LISTEN_CFG['port']))

    async with server:
        await server.serve_forever()

# bootstrap peers. connect to hardcoded peers
async def bootstrap():
    for host, port in const.PRELOADED_PEERS:
        peer = Peer(host, port)
        await connect_to_node(peer)


# connect to some peers
def resupply_connections():
    # If we have less than the threshold of connections, connect to more peers
    if len(CONNECTIONS) < const.LOW_CONNECTION_THRESHOLD:

        available_peers = list(PEERS - set(CONNECTIONS.keys()))

        random.shuffle(available_peers)

        for peer in available_peers[:MAX_CONNECTIONS - len(CONNECTIONS)]:
            asyncio.create_task(connect_to_node(peer))


async def init():
    global BLOCK_WAIT_LOCK
    BLOCK_WAIT_LOCK = asyncio.Condition()
    global TX_WAIT_LOCK
    TX_WAIT_LOCK = asyncio.Condition()

    PEERS.update(peer_db.load_peers())

    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())

    # Service loop
    while True:
        print("Service loop reporting in.")
        print("Open connections: {}".format(set(CONNECTIONS.keys())))

        # Open more connections if necessary
        resupply_connections()

        await asyncio.sleep(const.SERVICE_LOOP_DELAY)

    await bootstrap_task
    await listen_task


def main():
    asyncio.run(init())


if __name__ == "__main__":
    if len(sys.argv) == 3:
        LISTEN_CFG['address'] = sys.argv[1]
        LISTEN_CFG['port'] = sys.argv[2]

    main()
