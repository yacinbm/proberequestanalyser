#!/usr/bin/env python3
"""!
    @file cli.py
    @brief Probe Request analyzer - CLI

    @author Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    Inspired by wifite (https://github.com/derv82/wifite)
    
    This application aims to estimate the distance of a user based on the strength 
    of the received probe requests coming from a device. It uses scaby to sniff
    live traffic from the air and analyzes the packets directly.

    When launched with the --log option, the CLI will generate two log files,
    a .pcap and a .csv file to conserve the captured data. It will also create or
    update a local capture.db database. You can then read back that database with 
    the --printDb option, and pipe it to a file with ex.:
    @code sudo ./cli --printDb --noCap > database.txt
    @endcode

    For help on how to use the app, run with -h or --help.

    TODO:
        * Identify most relevant fields
"""
VERSION_STRING = "V0.1" #!< CLI Version String

import os # File management
from shutil import which # Python implementation of which
from datetime import datetime
from pathlib import Path

# Terminal interface
import sys
import argparse # Argument parsing

# Import top level directory
sys.path.insert(0,'../../')

# Capture Engine Module
from proberequestanalyzer.source.captureEngine import CaptureEngine

# Colored prints
from proberequestanalyzer.source.cliColors import bcolors

# SQLite3
import proberequestanalyzer.source.sqlManager as sql

# Database Constants
DB_NAME = "captures.db" #!< Name of the local SQLite database
TABLE_NAME = "captures" #!< Name of the SQLite database table

def programInstalled(programName):
    """! Returns true iff the program is installed on the machine.
    @param programName (str) Name of the program
    """
    return which(programName)

def checkDependencies():
        """! Check if all shell dependencies are installed on the current machine.
        @return True iff all dependencies are installed, else returns false
        """
        dependencies = ["aircrack-ng", "airodump-ng"]
        for dep in dependencies:
            if programInstalled(dep) is None:
                print(f"{bcolors.FAIL}Probe Request Capture requires {dep} installed. "
                       f"Please install aircrack-ng using:\n\tsudo apt-get install aicrack-ng{bcolors.ENDC}")
                return False
        return True

def __buildParser():
    parser = argparse.ArgumentParser()

    # Set options
    optionGroup = parser.add_argument_group("OPTIONS")
    optionGroup.add_argument("--numPackets", help="Number of packets to be captured. ",
                                type=int, action="store", dest="numPackets", default=10)
    optionGroup.add_argument("--interface", help="Interface to do capture on. "
                                "If no interface is selected, the first compatible one will be used.",
                                type=str, action="store", dest="interface", default=None)
    optionGroup.add_argument("--logPath", help="Path to the log directory where you want to automatically save the raw captures."
                                "If no path is given, the raw data won't be saved to the disk." ,
                                type=str, action="store", dest="logPath", default=False)
    optionGroup.add_argument("--noCap", help="Doesn't capture anything. Useful to print db without doing a capture.",
                                action="store_true", dest="noCap", default=False)
    optionGroup.add_argument("--printDb", help="Prints the contents of the database to the console. "
                                "You can output the results to a text file by echoing to a text file.",
                                action="store_true", dest="printDb", default=False)

    return parser

def main():
    """! 
    Entry point of the script.
    """
    print(f"{bcolors.HEADER}{bcolors.BOLD}=== Probe Request analyzer V{VERSION_STRING} ==={bcolors.ENDC}")
    # Build the argument parser
    parser = __buildParser()
    
    # Parse arguments
    options = parser.parse_args()
    
    # Create capture engine
    if not options.noCap:
        engine = CaptureEngine(options.interface, logPath=options.logPath)

        engine.startCapture()
        
        # Capture until we catch a packet
        while len(engine.capturedPackets) < options.numPackets:
            continue
        
        engine.stopCapture()
        print(f"Finished capturing {options.numPackets} packets.")

        pkts = engine.capturedPackets
        
        # Extract relevant data fields
        df = engine.getDataFrame(pkts)
    
        if options.logPath :
            # Create output folder
            Path("./log").mkdir(parents=True, exist_ok=True)
            print("Saving extracted data to csv...")
            dateTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            
            # Save dataframe
            df.to_csv(f"./log/dataFrame_{options.interface}_{dateTime}.csv")
            
            # Save to SQLite
            print("Saving extracted data to local sql db...")
            # Get connection
            conn = sql.createConnection(DB_NAME)
            # Save to database
            sql.saveToDb(conn,TABLE_NAME,df)
            # Close connection
            conn.close()

        print("Cleaning up...")
        engine.exitGracefully()
    
    # Print the contents of the DB
    if options.printDb:
        conn = sql.createConnection(DB_NAME)
        print(sql.getColumnsName())
        for row in sql.fetchAll(conn, TABLE_NAME):
            print(row)

if __name__ == "__main__":
    if os.getuid() != 0:
        exit(f"{bcolors.FAIL}Run as root.{bcolors.ENDC}")
    
    # Keyboard Interrupt handleing
    try:
        checkDependencies()
        main()
    except Exception as e:
        print(f"{bcolors.FAIL}{e}\nCleaning up...{bcolors.ENDC}")
        try:
            engine = CaptureEngine.getInstance()
            engine.exitGracefully()
        except:
            os._exit(0)