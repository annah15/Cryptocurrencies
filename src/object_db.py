import sqlite3

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
                      data TEXT)''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS transactions
                        (id TEXT PRIMARY KEY,
                         data TEXT)''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS block_transactions
                        (blockid TEXT,
                        txid TEXT,
                        FOREIGN KEY(blockid) REFERENCES blocks(id),
                        FOREIGN KEY(txid) REFERENCES transactions(id))''')          

        # Preload genesis block
        genesis_block = canonicalize(const.GENESIS_BLOCK)
        genesis_block_row = (const.GENESIS_BLOCK_ID, genesis_block)
        cur.execute("INSERT INTO blocks VALUES (?,?)", genesis_block_row)

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

def store_object(obj_id, obj_dict):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        if obj_dict["type"] == "block":
            cur.execute("INSERT INTO blocks VALUES (?,?)", (obj_id, canonicalize(obj_dict)))
        else:
            cur.execute("INSERT INTO transactions VALUES (?,?)", (obj_id, canonicalize(obj_dict)))
        con.commit()
        print("Object stored successfully!")
    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()

def fetch_object(obj_id, obj_type=None):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        #try to find the object in the blocks table if the type is block or not specified
        if obj_type == "block" or not obj_type:
            cur.execute("SELECT data FROM blocks WHERE id=?", (obj_id,))
            row = cur.fetchone()
        #try to find the object in the transactions table if the type is transaction or not specified and the object was not found in the blocks table
        if obj_type == "transaction" or (not obj_type and not row):
            cur.execute("SELECT data FROM transactions WHERE id=?", (obj_id,))
            row = cur.fetchone()
        # return the object dictionary if it was found
        if row:
            return json.loads(row[1])
        else:
            return None
    except Exception as e:
        print(str(e))
    finally:
        con.close()