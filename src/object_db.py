import sqlite3

import objects
import constants as const

def create_db():
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        # Create database
        # Create table
        cur.execute('''CREATE TABLE IF NOT EXISTS blocks
                     (blockid TEXT PRIMARY KEY,
                     created INTEGER,
                     miner TEXT,
                     nonce TEXT,
                     note TEXT
                     prev TEXT,
                     target INTEGER,
                    )''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS transactions
                        (txid TEXT PRIMARY KEY,
                        created INTEGER,
                        miner TEXT,
                        nonce TEXT,
                        note TEXT,
                        type TEXT)''')
        
        cur.execute('''CREATE TABLE IF NOT EXISTS block_transactions
                        (block_id TEXT,
                        tx_id TEXT,
                        FOREIGN KEY(block_id) REFERENCES blocks(id),
                        FOREIGN KEY(tx_id) REFERENCES transactions(id))''')          

        # TODO - Preload genesis block

        # Save (commit) the changes
        con.commit()
        print("Database created successfully!")
    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()
