#!/usr/bin/env python3
"""!
    @file probe_request_capture.py
    @brief Probe Request capture

    @author Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    Captures probe requests over a compatible monitor interface. It updates an 
    SQLite database with the extracted data fields from the probe requests.

    The application runs forever, and is meant to be used as a Docker Container application.
    It is meant to capture data forever and append sync with the database on a set
    interval.

    TODO:
        * The WiFi interface should not be managed by the application, as the drivers
          should be handled by the Host. The application should return with an error
          if monitor interface was detected.
"""
## CLI Version String
VERSION_STRING = "V0.1"

import os # File management
from shutil import which # Python implementation of which
from datetime import datetime
from pathlib import Path

# Terminal interface
import sys
import argparse # Argument parsing

# Import top level directory
sys.path.insert(0,'../')

from source.captureEngine import CaptureEngine
from source.cliColors import bcolors
import source.sqlUtil as sql
from source.wifiUtil import *

# Database Constants
## Time interval for syncing with the SQLite database in seconds
DB_SYNC_INTERVAL = 60
## Name of the SQLite database table
TABLE_NAME = "captures"

def __buildParser():
    parser = argparse.ArgumentParser()

    # Set options
    optionGroup = parser.add_argument_group("OPTIONS")
    optionGroup.add_argument("--interface", help="Interface to do capture on. "
                                "If no interface is selected, the first compatible one will be used.",
                                type=str, action="store", dest="interface", default=None)
    optionGroup.add_argument("--logPath", help="Path to the log directory where you want to automatically save the raw captures."
                                "If no path is given, the raw data won't be saved to the disk."
                                "The log path should be mapped to outside of the container, or the files will be deleted." ,
                                type=str, action="store", dest="logPath", default=False)
    optionGroup.add_argument("--dbAddress", help="Address of the SQLite database." 
                                "If no address is specified, the database is saved in the log folder.",
                                type=str, action="store", dest="dbAddress", default="captures.db")

    return parser

def saveData(pktData, log=False):
    """! @brief Saves the packet data to the SQLite database.
        This function is called every time the saveDataTimer expires in order to sync the database 
        with the captured data.
        @param pktData \b list Pandas Dataframe containing packet data.
        @param log [Optional]\b bool Indicate if the extra log data should be saved to the disk.
    """
    # TODO
    pass

def __timerCallback():
    """
        Extract the data from the captured packets
        Clear the packet list from the engine
        Save the data to the DB
    """
    captureEngine = CaptureEngine.getInstance()
    pkts = captureEngine.capturedPackets
    # Clear old packet data
    captureEngine.clearCapturedData()
    # Extract packet data and save to DB
    pktData = CaptureEngine.buildDataframe(pkts)
    saveData(pktData)


def main():
    """! @brief Entry point of the script.

    TODO:
        * Have repeating thread to extract data from captured packets
    """
    print(f"{bcolors.HEADER}{bcolors.BOLD}=== Probe Request analyzer {VERSION_STRING} ==={bcolors.ENDC}")
    # Build the argument parser
    parser = __buildParser()
    
    # Parse arguments
    options = parser.parse_args()
    
    # Create capture engine
    interface = setupIface(options.interface)
    engine = CaptureEngine(interface)
    engine.startCapture()
    
    # Capture forever
    while True:
        continue 


if __name__ == "__main__":
    if os.getuid() != 0:
        exit(f"{bcolors.FAIL}Run as root.{bcolors.ENDC}")
    
    try:
        main()
    # Keyboard Interrupt handling
    except KeyboardInterrupt:
        print("Interrupted, exiting...")
        try:
            engine = CaptureEngine.getInstance()
            engine.stopCapture()
            numCapturedPkts = len(engine.capturedPackets)
            print(f"Captured {numCapturedPkts} packets.")
        finally:
            os._exit(0)
    
    # Exception Handling
    except Exception as e:
        print(f"{bcolors.FAIL}{e}\nCleaning up...{bcolors.ENDC}")
        try:
            engine = CaptureEngine.getInstance()
            engine.stopCapture()
            print(len(engine.capturedPackets))
        finally:
            os._exit(0)