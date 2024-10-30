import sqlite3

import objects
import constants as const

from jcs import canonicalize

def create_db():
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
