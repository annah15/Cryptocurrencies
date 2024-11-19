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
        raise ErrorInvalidFormat('Invalid transaction input dictionary!')
    
    #Validate the outpoint
    outpoint = in_dict['outpoint']
    if sorted(list(outpoint.keys())) != sorted(['txid', 'index']):
        raise ErrorInvalidFormat('Invalid transaction outpoint dictionary!')
    if not isinstance(outpoint['txid'], str):
        raise ErrorInvalidFormat("txid not a string!")
    if not validate_objectid(outpoint['txid']):
        raise ErrorInvalidFormat("Invalid txid in outpoint!")
    if not isinstance(outpoint['index'], int):
        raise ErrorInvalidFormat('Outpoint index not an int!')
    
    #VerValidate the signature
    if not isinstance(in_dict['sig'], str):
        raise ErrorInvalidFormat("sig not a string!")
    if not validate_signature(in_dict['sig']):
        raise ErrorInvalidFormat("Invalid signature syntax!")
    
    return True

def validate_transaction_output(out_dict):
    #Check if the output is a dictionary with the correct keys 
    if sorted(list(out_dict.keys())) != sorted(['value', 'pubkey']):
        raise ErrorInvalidFormat('invalid transaction output dictionary.')
    
    #Validate the value
    if(not isinstance(out_dict['value'], int) or out_dict['value'] < 0):
        raise ErrorInvalidFormat('invalid transaction value.')
    
    #Validate the pubkey
    if not isinstance(out_dict['pubkey'], str) or not validate_pubkey(out_dict['pubkey']):
        raise ErrorInvalidFormat("invalid transaction pubkey.")
    
    return True

# Syntactic checks
def validate_transaction(trans_dict):
    #Check if the transaction is a dictionary with the correct keys 
    if sorted(list(trans_dict.keys())) != sorted(['type', 'inputs', 'outputs']) and sorted(list(trans_dict.keys())) != sorted(['type', 'height', 'outputs']):
        raise ErrorInvalidFormat('Invalid transaction keys: {}.'.format(trans_dict))
    
    # Validate the outputs
    if not isinstance(trans_dict['outputs'], list):
        raise ErrorInvalidFormat("Transaction object invalid: Outputs key not a list")
    index = 0
    for output in trans_dict['outputs']:
        try:
            validate_transaction_output(output)
        except ErrorInvalidFormat as e:
            raise ErrorInvalidFormat(f"Transaction object invalid: Output at index {index} invalid: {e.message}")
        index += 1

    #Check for coinbase transaction
    if('height' in trans_dict):
        # Validate height and input of coinbase transaction
        if not isinstance(trans_dict['height'], int):
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Height not an integer")
        if trans_dict['height'] < 0:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Negative height")
        if len(trans_dict['outputs']) > 1:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: More than one output set")
    else:
        # Validate the inputs of normal transaction
        if not isinstance(trans_dict['inputs'], list):
            raise ErrorInvalidFormat("Normal transaction object invalid: Inputs not a list")
        if len(trans_dict['inputs']) == 0:
            raise ErrorInvalidFormat(f"Normal transaction object invalid: No input set")

        for input in trans_dict['inputs']:
            try:
                validate_transaction_input(input)
            except ErrorInvalidFormat as e:
                raise ErrorInvalidFormat(f"Normal transaction object invalid: Input at index {index} invalid: {e.message}")
            index += 1

    return True

# Syntactic checks
def validate_block(block_dict):
    if not isinstance(block_dict, dict):
        raise ErrorInvalidFormat("Block object invalid: Not a dictionary!")
    #Check if the block is a dictionary with the correct keys 
    required_keys = {'type', 'txids', 'nonce', 'previd', 'created', 'T'}
    optional_combinations = [
    set(),  # No optional keys
    {'miner'},{'note'},{'miner', 'note'}]
    if not any(set(block_dict.keys()) == required_keys | optional for optional in optional_combinations):
        raise ErrorInvalidFormat(f'Invalid block keys: {block_dict.keys()}.')

    #Validate the transaction identifiers
    if not isinstance(block_dict['txids'], list):
        raise ErrorInvalidFormat("Block object invalid: txids is not a list.")
    if not all(validate_objectid(txid)for txid in block_dict['txids']):
        raise ErrorInvalidFormat("Block object invalid: txids contains object id with invalid format.")

    #Validate the nonce
    if not validate_nonce(block_dict['nonce']):
        raise ErrorInvalidFormat("Block object invalid: Incorrect nonce format.")
    
    #Validate the object identifier to the prev block (it can be 0 or a valid object id)
    if block_dict["previd"] == None and get_objid(block_dict) != const.GENESIS_BLOCK_ID:
        raise ErrorInvalidFormat("Block object invalid: previd is null but block i not genesis.")
    elif not isinstance(block_dict['previd'], str): 
        raise ErrorInvalidFormat("Block object invalid: previd is not a string.")
    elif not validate_objectid(block_dict["previd"]):
        raise ErrorInvalidFormat("Block object invalid: previd is not a correct object id.")

    #Validate the creation timestamp
    if not isinstance(block_dict['created'], int):
        raise ErrorInvalidFormat("Block object invalid: Creation timestamp not an integer.")
    if block_dict['created'] < 0:
        raise ErrorInvalidFormat("Block object invalid: created timestamp smaller than zero")
    try:
        datetime.fromtimestamp(block_dict['created'])
    except Exception:
        raise ErrorInvalidFormat("Block object invalid: created timestamp could not be parsed!")

    
    #Validate the target
    if not isinstance(block_dict['T'], str):
        raise ErrorInvalidFormat("Block object invalid: T not a string!")
    if not validate_target(block_dict['T']):
        raise ErrorInvalidFormat("Block object invalid: Incorrect target format.")
    
    #Validate miner if exists
    if(block_dict['miner'] and ((not block_dict['miner'].isprintable()) or (len(block_dict['miner']) > 128))):
        raise ErrorInvalidFormat('Block object invalid: miner is of incorrect format.')
    
    #Validate note if exists
    if(block_dict['note'] and ((not block_dict['note'].isprintable()) or (len(block_dict['note']) > 128))):
        raise ErrorInvalidFormat('Block object invalid: note is of incorrect format.')
    
    #Validate Poof of Work
    block_id = get_objid(block_dict)
    if (int(block_id,16) >= int(const.BLOCK_TARGET, 16)):
        raise ErrorInvalidBlockPow("Block object invalid: proof-of-work not satisfied.")

    return True

def validate_object(obj_dict):
    if not isinstance(obj_dict, dict):
        raise ErrorInvalidFormat("Object invalid: Not a dictionary!")
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
        return True
    except InvalidSignature:
        return False

# Verify the signatures of inputs with the corresponding transaction
def verify_transaction(tx_dict, prev_txs):
    # coinbase transaction
    if 'height' in tx_dict:
        return # assume all syntactically valid coinbase transactions are valid

    input_tx_dict = dict()
    msg = copy.deepcopy(tx_dict)
    # Replace all signatures by none to retrieve the plaintext message
    for i in range(len(msg["inputs"])):
        msg["inputs"][i]['sig']= None

    sum_of_inputs = 0

    for input in tx_dict['inputs']:
        out_id = input['outpoint']['txid']
        out_idx = input['outpoint']['index']

        #check for double spending
        if out_idx in input_tx_dict:
            if out_idx in input_tx_dict[out_id]:
                raise ErrorInvalidTxConservation(f"The same input ({out_id}, {out_idx}) was used multiple times in this transaction")
            else:
                input_tx_dict[out_id].add(out_idx)

        else:
            input_tx_dict[out_id] = {out_idx}

        
        # Check if the transaction exists in database
        if out_id not in prev_txs:
            raise ErrorUnknownObject('Transaction outpoint not found in database.'.format(out_id))

        prev_tx = prev_txs[out_id]
        # Verify output with given index exists
        if(out_idx >= len(prev_tx['outputs'])):
            raise ErrorInvalidTxOutpoint('Transaction index is out of scope: {}.'.format(out_idx))
        
        prev_tx_output = prev_tx['outputs'][out_idx]
        # Verify the the signature
        if not verify_tx_signature(msg, input['sig'], prev_tx_output['pubkey']):
            raise ErrorInvalidTxSignature('Invalid signature: {}.'.format(input['sig']))
        
        sum_of_inputs += prev_tx_output['value']

    # Check whether the weak law of conservation of value holds
    if sum_of_inputs < sum([o['value'] for o in tx_dict['outputs']]):
        raise ErrorInvalidTxConservation('Sum of outputs is larger than sum of inputs.')


# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, txid, utxo):
    invalue = 0
    for input_tx in tx['inputs']:
        input_tx_id = input_tx['outpoint']['txis']
        input_tx_idx = input_tx['outpoint']['index']
        
        # For each input, check if it is in the UTXO set and remove it
        if input_tx_id not in utxo :
            raise ErrorInvalidTxOutpoint("Transaction {} spends from an transaction that has already been spent.".format(txid))
        if input_tx_idx not in utxo[input_tx_id] :
            raise ErrorInvalidTxOutpoint("Transaction {} spends from an transaction that has already been spent.".format(txid))
        
        invalue = invalue + utxo[input_tx_id][input_tx_idx]

        # delete the corresponding index
        del utxo[input_tx_id][input_tx_idx]
        # if no indices of transaction exist in utxo delete entry
        if len(utxo[input_tx_id]) == 0:
            del utxo[input_tx_id]

        #Add transaction outputs to utxo
        outvalue = 0
        for idx, output in enumerate(tx['outputs']):
            utxo[txid].update({idx: output['value']})
            outvalue += output['value']
        
        if outvalue > invalue:
            raise ErrorInvalidTxOutpoint("Outputs for Transaction {} exceed inputs!".format(txid))

    return invalue - outvalue

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):

    # check block timestamp
    prev_created_ts = prev_block['created']
    if prev_created_ts >= block['created']:
        raise ErrorInvalidBlockTimestamp("Block not created after previous block!")

    height = prev_height + 1

     # no transactions, return old UTXO and height
    if len(block['txids']) == 0:
        return prev_utxo, height
    
    utxo = {} if prev_utxo is None else copy.deepcopy(prev_utxo)
    
    first_coinbase = 'height' in txs[block["txids"][0]]
    coinbase_txid = None
    coinbase_tx =  None
    
    if first_coinbase:
        coinbase_txid = block["txids"][0] 
        coinbase_tx = txs[coinbase_txid]
        # The height of a coinbase transaction does not match the height of the block that references it
        if coinbase_tx['height'] != height:
            raise ErrorInvalidBlockCoinbase("Coinbase transaction does not have the correct height. Block height is {}, coinbase height is {}.".format(height, coinbase_tx['height']))

    tx_fees = 0
    for txid in block["txids"][1:] if first_coinbase else block["txids"]:
        tx = txs[txid]

        # A coinbase transaction was referenced but is not at the first position or more than one coinbase transaction is referenced in a block.
        if 'height' in tx:
            raise ErrorInvalidBlockCoinbase("Coinbase transaction can only be at the first position of referrenced transactions.")
        
        # Check if it spends from the coinbase transaction
        if any(input['outpoint']['txid'] == coinbase_txid for input in tx['inputs']):
            raise ErrorInvalidTxOutpoint("Transaction {} spends from the coinbase transaction of the same block.".format(tx))

        tx_fees += update_utxo_and_calculate_fee(tx, txid, utxo)

    # check coinbase output value
    if coinbase_tx is not None:
        if coinbase_tx['outputs'][0]['value'] > const.BLOCK_REWARD + tx_fees:
            raise ErrorInvalidBlockCoinbase("Coinbase TX output value too big")

    return utxo, height
