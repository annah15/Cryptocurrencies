import sqlite3

from message.msgexceptions import * 

import objects
import constants as const
import os
import json

from jcs import canonicalize

def create_db():
    if os.path.exists(const.DB_NAME):
        print("Database already exists...")
        return
    
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        # Create database
        # Create table
        cur.execute('''CREATE TABLE IF NOT EXISTS blocks
                     (id TEXT PRIMARY KEY,
                      data TEXT,
                      utxo TEXT,
                      height INTEGER NOT NULL)''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS transactions
                        (id TEXT PRIMARY KEY,
                         data TEXT)''')
        
        # Preload genesis block
        genesis_block = canonicalize(const.GENESIS_BLOCK)
        genesis_block_row = (const.GENESIS_BLOCK_ID, genesis_block, None, 0)
        cur.execute("INSERT INTO blocks VALUES (?,?,?,?)", genesis_block_row)

        # Save (commit) the changes
        con.commit()
        print("Database created successfully!")
    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()

def object_exists(objid):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        #try to find the object in the blocks table
        cur.execute("SELECT * FROM blocks WHERE id=?", (objid,))
        row = cur.fetchone()
        if not row:
            #try to find the object in the transactions table
            cur.execute("SELECT * FROM transactions WHERE id=?", (objid,))
            row = cur.fetchone()
        return row is not None
    except Exception as e:
        print(str(e))
    finally:
        con.close()

def store_object(obj_id, obj_dict, utxo_set=None, height=None):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        if obj_dict["type"] == "transaction":
            cur.execute("INSERT INTO transactions VALUES (?,?)", (obj_id, canonicalize(obj_dict)))
        elif obj_dict["type"] == "block" and height:
            cur.execute("INSERT INTO blocks VALUES (?,?,?,?)", (obj_id, canonicalize(obj_dict), canonicalize(utxo_set), height))
        else: 
            if height is None:
                raise Exception("Height is not defined") # logic error
            else:
                raise Exception("Unknown object type: " + obj_dict["type"]) #assert: false
        con.commit()
        print("Object stored successfully!")
    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()

def fetch_object_data(obj_id, obj_type=None):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        #try to find the object in the blocks table if the type is block or not specified
        if obj_type == "block" or not obj_type:
            cur.execute("SELECT data FROM blocks WHERE id=?", (obj_id,))
            data = cur.fetchone()
        #try to find the object in the transactions table if the type is transaction or not specified and the object was not found in the blocks table
        if obj_type == "transaction" or (not obj_type and not data):
            cur.execute("SELECT data FROM transactions WHERE id=?", (obj_id,))
            data = cur.fetchone()
        # return the object dictionary if it was found
        if data:
            return json.loads(data[0])
        else:
            return None
    except Exception as e:
        print(str(e))
    finally:
        con.close()

def fetch_block(block_id):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        #try to find the object in the blocks table if the type is block or not specified
        cur.execute("SELECT * FROM blocks WHERE id=?", (block_id,))
        data = cur.fetchone()
        # return the object dictionary if it was found
        if data:
            block_data = json.loads(data[1])
            if block_data['type'] != 'block':
                raise ErrorInvalidFormat("Object id {} references transaction instead of block".format(block_id))
            #If utxo set exists, deserialize it
            utxo_set = json.loads(data[2]) if data[2] else None
            return block_data, utxo_set, data[3] # Returns: (block_data, utxo_set, height)
        else:
            return None, None, 0
    except Exception as e:
        print(str(e))
    finally:
        con.close()

    # returns the chaintip blockid + height
def fetch_chaintip_blockid():
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        res = cur.execute("SELECT id, height FROM blocks ORDER BY height DESC LIMIT 1")
        row = res.fetchone()
        if row is None:
            raise Exception("Assertion error: Not even the genesis block in database")

        return (row[0], row[1])
    except Exception as e:
        # assert: false
        con.rollback()
        raise e
    finally:
        con.close()