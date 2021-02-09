"""
    Probe Request Analyser

    Author: Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    Inspired by wifite (https://github.com/derv82/wifite)
    
    This application aims to estimate the distance of a user based on the strength 
    of the received probe requests coming from a device. It uses scaby to sniff
    live traffic from the air and analyses the packets directly.

    For help on how to use the app, run with -h or --help.

    =========================
    = QCA6174A INSTALLATION =
    =========================
    When using this program with the QCA6174A, you need to install a custom firmware
    that supports rawmode and cryptmode. You can use the firmware found at
    https://github.com/kvalo/ath10k-firmware/raw/master/QCA6174/hw3.0/4.4.1.c3/firmware-6.bin_WLAN.RM.4.4.1.c3-00075.
    Download the firmware file and rename it to firmware-2.bin. Now to install the
    firmware:
    (Note, the card used in the buspas module is hw3.0)
        * Back up the original firmware for your machine:
            cd /lib/firmware/ath10k/QCA6174
            sudo cp -r hw[hw_version] hw[hw_version]_ori
        * Remove the old firmware files:
            sudo rm /hw[hw_version]/firmware-*.bin
        * Copy the new firmware file:
            sudo cp /path/to/fw_file/[your firmware] ./firmware-2.bin
    
    Now in order to use a more recent firmware, you need to use a recent driver. For this,
    we use backports. Download backport v5.3.6-1 from
    https://cdn.kernel.org/pub/linux/kernel/projects/backports/stable/ and extract it. In
    the backports folder, execute the following commands to build the ath10k driver:
        make defconfig-ath10k
        make -j4
        sudo make install
    Finally, create a driver configuration file under /etc/modprobe.d/ath10k_core.conf
    with the following lines:
        options ath10k_core rawmode=1
        options ath10k_core cryptmode=1

    Now reboot your system to make sure the wlan interface is still showing with ifconfig.

    TODO:
        - Filter the received request with a variable RSSI value
            * Have an input parameter that changes the threshold
"""
import os # File management
from shutil import which # Python implementation of which
import datetime

# Terminal interface
from sys import argv # CLI input parameters
from sys import stdout # 
import argparse # Argument parsing

# Executing external processes
import subprocess

# Regular expression for terminal output parsing
import re

# Terminal colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# External modules
try:
    from scapy.all import *
except ImportError:
    exit(f"{bcolors.FAIL}Scapy is required for this application, please install with"
            f"\n\tpip install scapy{bcolors.ENDC}")

try:
    from netaddr import *
except ImportError:
    exit(f"{bcolors.FAIL}Netaddr is required for this application, please install with"
            f"\n\tpip install netaddr{bcolors.ENDC}")

try:
    import pandas as pd
except ImportError:
    exit(f"{bcolors.FAIL}Pandas is required for this application, please install with"
            f"\n\tpip install pandas{bcolors.ENDC}")

def programInstalled(programName):
    """
        Return true iff the program is installed on the machine.
    """
    return which(programName)

def checkDependencies():
        """
            Check if all wifi monitoring dependencies are installed.
            Returns true iff all dependencies are installed, else returns false
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
    optionGroup.add_argument("--filePath", help="File path to the pcap file to be analysed. "
                                "If no path is specified, will do capture over the air.",
                                type=str, action="store", dest="filePath", default=False)
    optionGroup.add_argument("--log", help="Enables logging to .pcap file.",
                                action="store_true", dest="log", default=False)

    return parser

def main():
    """
        This is where the magic happens.
    """
    print(f"{bcolors.HEADER}=== Probe Request Analyser V0.1 ==={bcolors.ENDC}")
    # Build the argument parser
    parser = __buildParser()
    
    # Parse arguments
    options = parser.parse_args()
    
     # Create capture engine
    engine = CaptureEngine(options.interface, filePath=options.filePath, log=options.log)

    engine.startCapture()
    
    # Capture until we catch a packet
    while len(engine.capturedPackets) < options.numPackets:
        continue
    
    engine.stopCapture()
    print(f"Finished capturing {options.numPackets} packets.")

    pkts = engine.capturedPackets
    
    # Extract relevant data fields
    df = engine.extractPacketData(pkts)
    if options.log :
        print("Saving extracted data to csv...")
        dateTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        df.to_csv(f"dataFrame_{options.interface}_{dateTime}.csv")
    
    engine.exitGracefully()

if __name__ == "__main__":
    if os.getuid() != 0:
        exit("Run as root.")
    
    # Keyboard Interrupt handleing
    try:
        main()
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR - {e}\nCleaning up...{bcolors.ENDC}")
        try:
            engine = CaptureEngine.getInstance()
            engine.exitGracefully()
        except:
            os._exit(0)