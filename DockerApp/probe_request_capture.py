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
# REMOVE THIS #
import sys
sys.path.append('/home/buspas/Code/wifi/proberequestanalyzer')
######################
## CLI Version String
VERSION_STRING = "V0.1"

import os # File management
import argparse # Argument parsing
from pathlib import Path 

from source.captureEngine import CaptureEngine
from source.cliColors import bcolors
import source.sqlUtil as sql
from source.wifiUtil import *
from source.threadUtil import RepeatTimer

# Database Constants
## Time interval for syncing with the SQLite database in seconds
DB_SYNC_INTERVAL = 10
## Name of the SQLite database table
TABLE_NAME = "captures"

def __saveData(logRaw, dbAddress=None):
    """
        @brief Saves the packet data to the SQLite database.
        This function is called every time the saveDataTimer expires in order to sync the database 
        with the captured data.
        @param logRaw \b bool Indicated wether or not a .pcap file should be created.
        @param dbAddress \b str Full path to the SQLite file, including the file name (e.g. "/log/myDb.db"). If none is given, create a db under ../log/capture.db
    """
    captureEngine = CaptureEngine.getInstance()
    # Save a copy of the data
    pkts = captureEngine.capturedPackets
    
    # Clear packet data buffer
    captureEngine.clearCapturedData()

    # Save the raw .pcap files
    if logRaw:
        captureEngine.saveCapFile(pkts)

    # Extract packet data and save to DB
    pktData = captureEngine.buildDataframe(pkts)
    
    # Create a db if none was given
    if dbAddress is None:
        # ../log
        logPath = Path(__file__).parent.absolute()/"log"
        logPath.mkdir(parents=True, exist_ok=True)
        # ../log/capture.db
        dbAddress = str(logPath/"capture.db")

    # Save data to SQLite DB
    con = sql.connect(dbAddress)
    sql.saveDfToDb(con, TABLE_NAME, pktData)
    
    print(f"Captured {len(pkts)} packets.")

def __buildParser():
    parser = argparse.ArgumentParser()

    # Set options
    optionGroup = parser.add_argument_group("OPTIONS")
    optionGroup.add_argument("--logRaw", help="Path to log raw captures. "
                                "If unspecified, raw caps are not stored.", 
                                action="store_true", dest="logRaw", default=False)
    optionGroup.add_argument("--dbAddress", help="Address of the SQLite database." 
                                "If no address is specified, the database is saved in the current folder.",
                                type=str, action="store", dest="dbAddress", default=None)

    return parser

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
    
    # Select first monitor mode interface
    ifaces = getMonCompatIfaces()
    selectediface = None
    for iface in ifaces.keys():
        if isMonitorMode(iface):
            selectediface = iface
            break
    
    if not selectediface:
        exit(f"{bcolors.FAIL}No monitor mode interface, enable using airmon-ng.{bcolors.ENDC}")

    # Setup engine and start capture
    engine = CaptureEngine(selectediface)
    engine.startCapture()
    
    # Start packet extraction timer 
    args = [options.logRaw, options.dbAddress]
    packetExtrTimer = RepeatTimer(DB_SYNC_INTERVAL, __saveData,args)
    packetExtrTimer.start()

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
        finally:
            os._exit(0)
    
    # Exception Handling
    except Exception as e:
        print(f"{bcolors.FAIL}{e}\nCleaning up...{bcolors.ENDC}")
        try:
            engine = CaptureEngine.getInstance()
            engine.stopCapture()
        finally:
            os._exit(0)