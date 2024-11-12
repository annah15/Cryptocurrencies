from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re

import constants as const
from message.msgexceptions import *
import object_db

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    return re.match(OBJECTID_REGEX, objid_str) is not None

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    return re.match(PUBKEY_REGEX, pubkey_str) is not None


SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    return re.match(SIGNATURE_REGEX, sig_str) is not None

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    return re.match(NONCE_REGEX, nonce_str) is not None


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    return re.match(TARGET_REGEX, target_str) is not None


def validate_transaction_input(in_dict):
    #Check if the input is a dictionary with the correct keys 
    if sorted(list(in_dict.keys())) != sorted(['sig', 'outpoint']):
        raise ErrorInvalidFormat('Invalid transaction field inputs: {}.'.format(in_dict))
    
    #Verify the outpoint
    if sorted(list(in_dict['outpoint'].keys())) != sorted(['txid', 'index']):
        raise ErrorInvalidFormat('Invalid transaction field outpoint: {}.'.format(in_dict['outpoint']))
    if not validate_objectid(in_dict['outpoint']['txid']):
        raise ErrorInvalidFormat('Invalid transaction outpoint txid: {}.'.format(in_dict['outpoint']['txid']))
    obj_dict = object_db.fetch_object(in_dict['outpoint']['txid'])
    # Check if the transaction exists in database
    if obj_dict is None:
        raise NonfaultyNodeException('Transaction outpoint not found in database: {}.'.format(in_dict['outpoint']['txid']), "UNKNOWN_OBJECT")
    if obj_dict["type"] != "transaction":
        raise ErrorInvalidFormat('Wrong object referenced: {}.'.format(in_dict['outpoint']['txid']))
    # Verify output with given index exists
    if not isinstance(in_dict['outpoint']['index'], int):
        raise ErrorInvalidFormat('Invalid transaction outpoint index: {}.'.format(in_dict['outpoint']['index']))
    if(in_dict['outpoint']['index'] >= len(obj_dict['outputs'])):
        raise ErrorInvalidTxOutpoint('Transaction index is out of scope: {}.'.format(in_dict['outpoint']['index']))
    
    #Verify the signature
    if not validate_signature(in_dict['sig']):
        raise ErrorInvalidFormat('Invalid transaction signature format: {}.'.format(in_dict['sig']))
    return obj_dict

def validate_transaction_output(out_dict):
    if sorted(list(out_dict.keys())) != sorted(['value', 'pubkey']):
        raise ErrorInvalidFormat('Invalid transaction output: {}.'.format(out_dict))
    if(not isinstance(out_dict['value'], int) or out_dict['value'] < 0):
        raise ErrorInvalidFormat('Invalid transaction value: {}.'.format(out_dict['value']))
    if not validate_pubkey(out_dict['pubkey']):
        raise ErrorInvalidFormat('Invalid transaction pubkey: {}.'.format(out_dict['pubkey']))
    return True

def validate_transaction(trans_dict):
    if sorted(list(trans_dict.keys())) != sorted(['type', 'inputs', 'outputs']) and sorted(list(trans_dict.keys())) != sorted(['type', 'height', 'outputs']):
        raise ErrorInvalidFormat('Invalid transaction msg: {}.'.format(trans_dict))
    # Validate the outputs
    for output in trans_dict['outputs']:
        validate_transaction_output(output)
    if('height' in trans_dict):
        if(not isinstance(trans_dict['height'], int) or trans_dict['height'] < 0):
            raise ErrorInvalidFormat('Transaction key height is invalid: {}.'.format(trans_dict['height']))
    else:
        # Check if the transaction has inputs and validate them
        input_tx_dicts = []
        if len(trans_dict['inputs']) == 0:
            raise ErrorInvalidFormat('Invalid transaction msg (no inputs found).')
        for input in trans_dict['inputs']:
            input_tx_dict = validate_transaction_input(input)
            input_tx_dicts.append(input_tx_dict)

        verify_transaction(trans_dict, input_tx_dicts)

        # Check whether the weak law of conservation of value holds
        sum_of_inputs = 0
        for i in trans_dict['inputs']:
            tx_dict = input_tx_dicts.pop(0)
            sum_of_inputs += tx_dict['outputs'][i['outpoint']['index']]['value']

        sum_of_outputs = 0
        for o in trans_dict['outputs']:
            sum_of_outputs += o['value']
        if(sum_of_inputs < sum_of_outputs):
            raise ErrorInvalidTxConservation('Sum of outputs is larger than sum of inputs: {}.'.format(trans_dict['inputs']))

    return True

def validate_block(block_dict):
    # todo
    return True

def validate_object(obj_dict):
    if 'type' not in obj_dict:
        raise ErrorInvalidFormat("Object does not contain key 'type'.")
    
    obj_type = obj_dict['type']
    if(obj_type == "transaction"):
        return validate_transaction(obj_dict)
    elif(obj_type == "block"):
        return validate_block(obj_dict)
    else:
        raise ErrorInvalidFormat("Object has invalid key 'type'.")


def get_objid(obj_dict):
    h = hashlib.blake2s()
    h.update(canonicalize(obj_dict))
    return h.hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    print('Verifying Signature')
    pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
    sig_bytes = bytes.fromhex(sig)
    try:
        pubkey.verify(sig_bytes, canonicalize(tx_dict))
    except InvalidSignature:
        raise ErrorInvalidTxSignature('Invalid signature: {}.'.format(sig))


class TXVerifyException(Exception):
    pass

# Verify the signatures of inputs with the corresponding transaction
def verify_transaction(tx_dict, input_txs):
    print("Verifying Transaction")
    msg = copy.deepcopy(tx_dict)
    # Replace all signatures by none to retrieve the plaintext message
    for i in range(len(msg["inputs"])):
        msg["inputs"][i]['sig']= None
    # Verify the signature for every input
    for input, data in zip(tx_dict["inputs"], input_txs):
        verify_tx_signature(msg, input["sig"], data['outputs'][input['outpoint']['index']]['pubkey'])



class BlockVerifyException(Exception):
    pass

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    # todo
    return 0

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    # todo
    return 0
