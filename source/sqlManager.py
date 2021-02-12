"""
    SQLite3 manager for the captured packets.

    This is used to save to a SQLite3 database, remotely, in memory or locally.

    Author: Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)
"""
import sqlite3

""" 
    Table Comlumns with their types
    You only need to add the fields and their types 
    to this table and they will automatically be inserted.
"""
TABLE_COLUMNS = [
    ("sender_addr","text"),
    ("random_mac","text"),
    ("manufacturer", "text"),
    ("dBm_AntSignal","integer"),
    ("ssid","text"),
    ("rates", "blob"),
    ("seq_num", "integer"),
    ("RX_MSC_Bitmask", "integer"),
    ("A_MPDU_ref", "integer"),
    ("mac_timestamp", "integer"),
    ("oui", "integer")
    ]

def createConnection(dbName):
    """
        Create connection to database.
    """
    try:
        conn = sqlite3.connect(dbName)
        return conn
    except Exception as e:
        print(e)

def getColumnsName():
    return [col[0] for col in TABLE_COLUMNS]

def saveToDb(connection, table, df):
    """
        Save dataframe to database. Needs a SQLite3 connection to database.
        You can add lines to the TABLE_COLUMNS to add fields to be saved.
    """
    # Create cursor
    c = connection.cursor()

    # Create table if not exist
    createTableIfNotExist = f"""CREATE TABLE IF NOT EXISTS {table}
        (""" + " ".join(f"{col[0]+' '+col[1]+','}" for col in TABLE_COLUMNS)[:-1] +");"
    c.execute(createTableIfNotExist)
    connection.commit()

    sqlRows = []
    for index, pktInfo in df.iterrows():
        # Create data Tuple
        row = []
        for col in TABLE_COLUMNS:
            name = col[0]
            val = pktInfo[name]
            row.append(val)
        sqlRows.append(tuple(row))

    # Insert data to table
    numQuestMark = len(TABLE_COLUMNS)
    questMarkStr = "("+"".join("?," for i in range(numQuestMark))[:-1]+")"
    c.executemany(f"INSERT INTO {table} VALUES {questMarkStr}", sqlRows)
    connection.commit()

def fetchAll(connection, table):
    """
        Returns a list of dictionnaries for every row of the db.
    """
    c = connection.cursor()
    c.execute(f"""SELECT * FROM {table}""")
    return [{c.description[i][0]:val for i, val in enumerate(entry)} for entry in c.fetchall()]