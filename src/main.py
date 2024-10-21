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
def add_peer(peer: Peer):
    global PEERS

    # Don't add banned hosts
    if peer.host in const.BANNED_HOSTS:
        return
    
    PEERS.add(peer)

# Add connection if not already open
def add_connection(peer, queue):
    global CONNECTIONS

    print("Adding connection with {}".format(peer))
    host, port = peer

    p = Peer(host, port)
    if p in CONNECTIONS:
        raise Exception("Connection with {} already open!".format(peer))

    CONNECTIONS[p] = queue


# Delete connection
def del_connection(peer):
    global CONNECTIONS
    host, port = peer
    del CONNECTIONS[Peer(host, port)]

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
        "peers": [str(const.ADDRESS) + ':' + str(LISTEN_CFG['port'])] + [str(peer) for peer in list(PEERS)[:29]]
    }

def mk_getobject_msg(objid):
    return {
        "type": "getobject",
        "objectid": objid
    }

def mk_object_msg(obj_dict):
    return {
        "type": "object",
        "object": obj_dict
    }

def mk_ihaveobject_msg(objid):
    return {
        "type": "ihaveobject",
        "objectid": objid
    }

def mk_chaintip_msg(blockid):
    return {
        "type": "chaintip",
        "blockid": blockid
    }

def mk_mempool_msg(txids):
    return {
        "type": "mempool",
        "txids": txids
    }

def mk_getchaintip_msg():
    return {
        "type": "getchaintip"
    }

def mk_getmempool_msg():
    return {
        "type": "getmempool"
    }

# parses a message as json. returns decoded message
def parse_msg(msg_str):
    print(f"Parsing: {msg_str}")
    try:
        msg_dict = json.loads(msg_str)
        return msg_dict
    except json.JSONDecodeError:
        raise MalformedMsgException("Invalid JSON format")

# Send data over the network as a message
async def write_msg(writer, msg_dict):
    writer.write(b''.join([canonicalize(msg_dict), b'\n']))
    await writer.drain()

# Check if message contains no invalid keys and all expected keys are present,
# raises a MalformedMsgException
def validate_allowed_keys(msg_dict:dict, allowed_keys:list, msg_type:str):
    if (sorted(list(msg_dict.keys())) != sorted(allowed_keys)):
        raise MalformedMsgException(f"Expected keys {allowed_keys} in {msg_type} message")


# Validate the hello message
# raises an exception
def validate_hello_msg(msg_dict):
    if "type" not in msg_dict:
        raise MalformedMsgException(f"Missing required key type in message")
    
    if msg_dict['type'] != 'hello':
        raise InvalidHandshakeException(f"First message must be a hello message")

    # Check for invalid and missing keys
    validate_allowed_keys(msg_dict, ['type', 'version', 'agent'], 'hello')

    # Validate version format (example: "1.10.x")
    if not re.match(r'^0\.10\.\d$', msg_dict['version']):
        raise MalformedMsgException(f"Version has to be in the format 0.10.x")

    # Validate agent key
    if (len(msg_dict['agent']) > 128 or not msg_dict['agent'].isprintable()):
        raise MalformedMsgException("Agent key has to be a printable string of maximum 128 characters")
    
# returns true iff host_str is a valid hostname
def validate_hostname(host_str):
   
    return re.match(r'^(?=.*[a-zA-Z])[a-zA-Z\d\.\-\_]{3,50}$', host_str) and '.' in host_str[1:-1]

# returns true iff host_str is a valid ipv4 address
def validate_ipv4addr(host_str):
    try:
        ipaddress.IPv4Address(host_str)
        return True
    except ipaddress.AddressValueError:
        return False

# returns true iff peer_str is a valid peer address
def validate_peer_str(peer_str):
    try:
        host, port = peer_str.split(':')
    except ValueError:
        raise MalformedMsgException("Peer string must be in the format host:port")
    if int(port)<1 or int(port)> 65535:
        raise MalformedMsgException("Port must be between 1 and 65535")
    if not (validate_hostname(host) or validate_ipv4addr(host)):
        raise MalformedMsgException("Invalid adress {}".format(host))


# raise an exception if not valid
def validate_peers_msg(msg_dict):

    validate_allowed_keys(msg_dict, ["type","peers"], "peers")

    peers = msg_dict['peers']

    if not isinstance(peers, list):
        raise MalformedMsgException("'peers' key must be an array")
    if len(peers) > 30:
        raise MalformedMsgException("List of peers must not exceed 30 entries")
    for peer in peers:
        validate_peer_str(peer)


# raise an exception if not valid
def validate_getpeers_msg(msg_dict):
    validate_allowed_keys(msg_dict, ['type'], 'getpeers')

# raise an exception if not valid
def validate_getchaintip_msg(msg_dict):
    validate_allowed_keys(msg_dict, ['type'], 'getchaintip')

# raise an exception if not valid
def validate_getmempool_msg(msg_dict):
    validate_allowed_keys(msg_dict, ['type'], 'getmempool')

# raise an exception if not valid
def validate_error_msg(msg_dict):
    validate_allowed_keys(msg_dict, ['type', 'name', 'msg'], 'error')

# raise an exception if not valid
def validate_ihaveobject_msg(msg_dict):
    validate_allowed_keys(msg_dict, ['type', 'objectid'], 'ihaveobject')

# raise an exception if not valid
def validate_getobject_msg(msg_dict):
    validate_allowed_keys(msg_dict, ['type', 'objectid'], 'getobject')

# raise an exception if not valid
def validate_object_msg(msg_dict):
    validate_allowed_keys(msg_dict, ['type', 'objectid'], 'object')

# raise an exception if not valid
def validate_chaintip_msg(msg_dict):
    validate_allowed_keys(msg_dict, ['type', 'blockid'], 'chaintip')

# raise an exception if not valid
def validate_mempool_msg(msg_dict):
    validate_allowed_keys(msg_dict, ['type', 'txids'], 'mempool')
        
def validate_msg(msg_dict):
    if "type" not in msg_dict:
        raise MalformedMsgException(f"Missing required key type in message")
    
    msg_type = msg_dict['type']
    if msg_type == 'hello':
        raise InvalidHandshakeException("Received hello message from already connected peer")
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
    global PEERS
    new_peers = msg_dict['peers']
    for peer_str in new_peers:
        host, port = peer_str.split(':')
        peer = Peer(host, int(port))

        if peer.host_str == const.ADDRESS and peer.port == LISTEN_CFG['port']:
            print("Received ourselves, skipping...")
            continue

        if peer not in PEERS:
            add_peer(peer)
            peer_db.store_peer(peer)

def handle_error_msg(msg_dict, peer_self):
    print("Received error of type {}: {}".format(msg_dict['name'], msg_dict['msg']))


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
async def handle_msg(msg_dict, writer):
    print("Handling received message: {}".format(msg_dict))
    # Determine message type and handle it accordingly
    msg_type = msg_dict['type']
    if msg_type == 'getpeers':
        await write_msg(writer, mk_peers_msg())
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

async def handle_queue_msg(msg_dict, writer):
    pass # TODO

# how to handle a connection
async def handle_connection(reader:asyncio.StreamReader, writer:asyncio.StreamWriter):
    read_task = None
    queue_task = None

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

    buffer = ""
    try:
        # Send initial messages
        await write_msg(writer, mk_hello_msg())
        asyncio.create_task(write_msg(writer, mk_getpeers_msg()))

        # Complete handshake
        # wait for hello message from peer and add it to buffer
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=const.HELLO_MSG_TIMEOUT)
        except asyncio.exceptions.TimeoutError:
            raise InvalidHandshakeException("No hello message received within 20s")
        buffer += data.decode()

        first_msg, buffer = re.split(r'(?<!\\)\n', buffer, 1)
        first_msg_dict = parse_msg(first_msg)

        # Validate the hello message (also checks if the message is a hello message)
        validate_hello_msg(first_msg_dict)
        
        # Add the connection to the list of connections
        add_connection(peer, queue)

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
            while re.search(r'(?<!\\)\n', buffer):
                # split the first message from the buffer
                msg, buffer = re.split(r'(?<!\\)\n', buffer, 1)
                # parse the message, validate it and handle it
                msg_dict = parse_msg(msg)
                validate_msg(msg_dict)
                await handle_msg(msg_dict, writer)

            # for now, close connection
            raise MessageException("closing connection")

    except InvalidHandshakeException as e:
        print("{}: {}".format(peer, str(e.message)))
        try:
            await write_msg(writer, mk_error_msg(e.message, "INVALID_HANDSHAKE"))
        except:
            pass
    except MalformedMsgException as e:
        print("{}: {}".format(peer, str(e)))
        try:
            await write_msg(writer, mk_error_msg(e.NETWORK_ERROR_MESSAGE, "INVALID_FORMAT"))
        except:
            pass
    except Exception as e:
        print("Error not handeled: {}: {}".format(peer, str(e)))
    finally:
        print("Closing connection with {}".format(peer))
        writer.close()
        if read_task is not None and not read_task.done():
            read_task.cancel()
        if queue_task is not None and not queue_task.done():
            queue_task.cancel()
        del_connection(peer)


# Connect to another node
async def connect_to_node(peer: Peer):
    try:
        reader, writer = await asyncio.open_connection(peer.host, peer.port,
                limit=const.RECV_BUFFER_LIMIT)
    except Exception as e:
        print(str(e))
        return

    await handle_connection(reader, writer)

# Start TCP server and listen for incoming connections
async def listen():
    server = await asyncio.start_server(handle_connection, LISTEN_CFG['address'],
            LISTEN_CFG['port'], limit=const.RECV_BUFFER_LIMIT)

    print("Listening on {}:{}".format(LISTEN_CFG['address'], LISTEN_CFG['port']))

    async with server:
        await server.serve_forever()

# bootstrap peers. connect to hardcoded peers
async def bootstrap():
    # Connect to preloaded peers
    for host, port in const.PRELOADED_PEERS:
        peer = Peer(host, port)
        task = asyncio.create_task(connect_to_node(peer))
        add_peer(peer)
        BACKGROUND_TASKS.add(task)
        task.add_done_callback(lambda t: BACKGROUND_TASKS.remove(t))

# connect to some peers
def resupply_connections():
    # If we have less than the threshold of connections, connect to more peers
    if len(CONNECTIONS) < const.LOW_CONNECTION_THRESHOLD:

        available_peers = list(PEERS - set(CONNECTIONS.keys()))

        random.shuffle(available_peers)

        for peer in available_peers[:MAX_CONNECTIONS - len(CONNECTIONS)]:
            task = asyncio.create_task(connect_to_node(peer))
            BACKGROUND_TASKS.add(task)
            task.add_done_callback(lambda t: BACKGROUND_TASKS.remove(t))

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
