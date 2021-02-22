"""!
    @file sqlUtil.py
    @brief SQLite manager for the extracted packet data Database.

    This is used to save to a SQLite3 database, remotely, in memory or locally.

    @author Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    TODO: 
        * Add other functions to fetch certain columns, or certain rows.
"""
import sqlite3
from cliColors import bcolors

class Database:
    """! SQLite3 database handeling object.
    Use:
        db = Database("myDatabase.db")
        myDataFrame = pandas.Dataframe()
        db.saveDfToDb(myDataFrame)
        
    @param dbAddr   (str) Address to the target database.
    """
    def __init__(self, dbAddr):
        """ Creates connection object to the database.
        """
        self.__conn = self.__createConnection(dbAddr)
    
    def __del__(self):
        """ Close the connection to the database.
        """
        self.__conn.close()

    def __createConnection(dbAddr):
    """ Connect to the target SQLite database.
    @param dbAddr   (str) Address of the SQLite database.
    @return (sqlite3.Connection) SQLite 3 connection object to the target database.
    """
    try:
        conn = sqlite3.connect(dbAddr)
        return conn
    except Exception as e:
        print(e)

    def getConnection(self):
        """@return SQLite3 connection object to the database.
        """
        return self.__conn

    def tableExists(self, tableName):
        """! Checks if the table exists in the database.
        @param tableName (str) Name of the target table
        @return Returns True iff the table exists in the database.
        """
        c = self.conn.cursor()
        c.execute(f"SELECT name FROM sqlite_master WHERE type=table AND name={tableName}")

        if c.fetchone()[0]:
            return True
        else:
            return False

    def getColumnsName(tableName):
        """! Returns a list of the names of the columns of the target table.
        @param tableName    (str) Name of the target table
        @return List of the column names of the target table. If the table does not exist, 
                returns an empty list.
        """
        if not self.tableExists(tableName):
            print(f"{bcolors.WARNING}Table {tableName} does not exist, cannot get column names.")
            return []
        cursor = self.conn.execute(f'select * from {tableName}')
        names = [description[0] for description in cursor.description]
        return names

    def saveDfToDb(tableName, df):
        """! Save Pandas dataframe to database.
        @param tableName (str) Name of the target table in the database.
        @param df   (pandas.DataFrame) Dataframe to be saved to the database.
                    The columns of the dataframe to be saved are defined in TABLE_COLUMNS.
        """
        # Create cursor
        c = self.conn.cursor()

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
                val = pktInfo[name]
                row.append(val)
            sqlRows.append(tuple(row))

        # Insert data to table
        numQuestMark = len(TABLE_COLUMNS)
        questMarkStr = "("+"".join("?," for i in range(numQuestMark))[:-1]+")"
        c.executemany(f"INSERT INTO {tableName} VALUES {questMarkStr}", sqlRows)
        
        # Commit the changes to the dataBase
        self.conn.commit()

    def fetchAll(connection, tableName):
        """! Returns a list of dictionnaries for every row of the table.
        @param connection   (sqlite3.Connection) Connection object to the target sqlite database.
        @param tableName    (str) Name of the target table.
        @return List of dictionnaries for every row of the table. If the table does not exist, return
                an empty list
        """
        if not self.tableExists(tableName):
            print(f"{bcolors.WARNING}Table {tableName} does not exist, cannot fetch data.")
            return []
        
        # Create cursor
        c = connection.cursor()
        
        c.execute(f"""SELECT * FROM {tableName}""")
        return [{c.description[i][0]:val for i, val in enumerate(entry)} for entry in c.fetchall()]