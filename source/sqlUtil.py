"""!
    @file sqlUtil.py
    @brief SQLite manager for the extracted packet data Database.

    This is used to save to a SQLite3 database, remotely, in memory or locally.

    @author Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    TODO: 
        * Add other functions to fetch certain columns, or certain rows.
"""
import sqlite3
from .cliColors import bcolors

def connect(dbAddr):
    """ Connect to the target SQLite database.
    @param dbAddr   (str) Address of the SQLite database.
    @return (sqlite3.Connection) SQLite 3 connection object to the target database. In case of an 
    error, returns None.
    """
    try:
        conn = sqlite3.connect(dbAddr)
        return conn
    except Exception as e:
        print(f"{bcolors.WARNING}{e}{bcolors.ENDC}")
        return None

def tableExists(connection, tableName):
    """! Checks if the table exists in the database.
    @param connection   (SQLite3 Connection Object) Connection object to the database.
    @param tableName (str) Name of the target table
    @return Returns True iff the table exists in the database.
    """
    c = connection.cursor()
    c.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{tableName}'")

    if c.fetchone()[0]:
        return True
    else:
        return False

def getColumnsName(connection, tableName):
    """! Returns a list of the names of the columns of the target table.
    @param connection   (SQLite3 Connection Object) Connection object to the database.
    @param tableName    (str) Name of the target table
    @return List of the column names of the target table. If the table does not exist, 
            returns an empty list.
    """
    if not tableExists(tableName):
        print(f"{bcolors.WARNING}Table {tableName} does not exist, cannot get column names.")
        return []
    cursor = connection.execute(f'select * from {tableName}')
    names = [description[0] for description in cursor.description]
    return names

def saveDfToDb(connection, tableName, df):
    """! Save Pandas dataframe to database.
    @param connection   (SQLite3 Connection Object) Connection object to the database.
    @param tableName (str) Name of the target table in the database.
    @param df   (pandas.DataFrame) Dataframe to be saved to the database.
                The columns of the dataframe to be saved are defined in TABLE_COLUMNS.
    """
    # Create cursor
    c = connection.cursor()

    """ 
    Default Table Comlumns with their types.
    Add fields  and their types to this table and they will automatically be inserted.
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

    # Create table if not exist
    createTableIfNotExist = f"""CREATE TABLE IF NOT EXISTS {tableName}
        (""" + " ".join(f"{col[0]+' '+col[1]+','}" for col in TABLE_COLUMNS)[:-1] +");"
    c.execute(createTableIfNotExist)
    connection.commit()

    sqlRows = []
    for index, pktInfo in df.iterrows():
        # Create data Tuple
        row = []
        for col in TABLE_COLUMNS:
            name = col[0]
            try:
                val = pktInfo[name]
            except:
                # Can't get value, set it to None
                val = None
            row.append(val)
        sqlRows.append(tuple(row))

    # Insert data to table
    numQuestMark = len(TABLE_COLUMNS)
    questMarkStr = "("+"".join("?," for i in range(numQuestMark))[:-1]+")"
    c.executemany(f"INSERT INTO {tableName} VALUES {questMarkStr}", sqlRows)
    
    # Commit the changes to the dataBase
    connection.commit()

def fetchAll(connection, tableName):
    """! Returns a list of dictionnaries for every row of the table.
    @param connection   (sqlite3.Connection) Connection object to the target sqlite database.
    @param tableName    (str) Name of the target table.
    @return List of dictionnaries for every row of the table. If the table does not exist, return
            an empty list
    """
    if not tableExists(connection, tableName):
        print(f"{bcolors.WARNING}Table {tableName} does not exist, cannot fetch data.")
        return []
    
    # Create cursor
    c = connection.cursor()
    
    c.execute(f"""SELECT * FROM {tableName}""")
    return [{c.description[i][0]:val for i, val in enumerate(entry)} for entry in c.fetchall()]