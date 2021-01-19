"""
    Probe Request Capture

    Author: Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    Inspired by wifite (https://github.com/derv82/wifite)

    TODO:
    Capture probe requests using airodump-ng
        - Create a structure to organize the requests per client (dict or data frame)
            * Have an input parameter that allows for saving the stucture
        - Filter the received request with a variable RSSI value
            * Have an input parameter that changes the threshold
        - Analyze the probe requests (sample function)
"""
import os # File management
from shutil import which # Python implementation of which
from time import sleep # Delay code execution

# Terminal interface
from sys import argv # CLI input parameters
from sys import stdout # 
import argparse # Argument parsing

# Executing external processes
import subprocess

def programInstalled(programName):
    """
        Return true iff the program is installed on the machine.
    """
    return which(programName)

def applyQca6174Fix():
    """
        Unload the ath10k driver module and load it back in rawmode and cryptmode.

        #TODO: This fix would be unecessary if the kernel module was loaded with the correct mode.
    """
    print("Applying the QCA6174 driver fix. Make sure you have the latest "
            "version of the ATH10k driver and a firmware compatible with rawmode "
            "and crypt mode.")
    output = subprocess.call(["modprobe", "-r", "ath10k_pci"],stdout=open(os.devnull, 'wb'))
    output = subprocess.call(["modprobe", "-r", "ath10k_core"],stdout=open(os.devnull, 'wb'))
    sleep(0.5)
    output = subprocess.call(["modprobe", "ath10k_core", "rawmode=1", "cryptmode=1"],stdout=open(os.devnull, 'wb'))
    output = subprocess.call(["modprobe", "ath10k_pci"],stdout=open(os.devnull, 'wb'))
    sleep(1)

def removeQca6174Fix():
    """
        Revert the ATH10K to its default state.
    """
    output = subprocess.call(["modprobe", "-r", "ath10k_pci"],stdout=open(os.devnull, 'wb'))
    output = subprocess.call(["modprobe", "-r", "ath10k_core"],stdout=open(os.devnull, 'wb'))
    sleep(0.1)
    output = subprocess.call(["modprobe", "ath10k_core", "rawmode=0", "cryptmode=0"],stdout=open(os.devnull, 'wb'))
    output = subprocess.call(["modprobe", "ath10k_pci"],stdout=open(os.devnull, 'wb'))

def setMonitorMode(interface):
    """
        Set the interface to monitor Mode using airmon-ng.
    """
    print(f"Setting {interface} in Monitor mode...")
    try:
        output = subprocess.call(["sudo", "airmon-ng", "start", interface], stdout=open(os.devnull, 'wb'))
        if output != 0:
            raise RuntimeError(f'airmon-ng start {interface} failed!')
    except RuntimeError as e:
        print(e)
        exit()

def disableMonitorMode(interface):
    """
        Set the current 
    """
    print(f"Setting {interface} back to in Managed mode...")
    try:
        output = subprocess.call(["sudo", "airmon-ng", "stop", interface], stdout=open(os.devnull, 'wb'))
        if output != 0:
            raise RuntimeError(f'airmon-ng stop {interface} failed!')
    except RuntimeError as e:
        exit(e)

def getCompatibleInterfaces():
    """
        Returns a dict of all compatible interfaces and their current operating mode.
    """
    output = subprocess.check_output(["iwconfig"],stderr=open(os.devnull, 'wb')).decode("utf-8").split("\n\n")
    output = list(filter(None, output)) # Remove empty strings
    if not output:
        exit("No compatible interface found. Make sure your wifi card supports Monitor mode.")
    
    interfaceDict = {}
    for interface in output:
        name = interface.split(" ")[0]
        mode = interface.split("Mode:")[1].split(" ")[0]
        interfaceDict[name] = mode
    return interfaceDict

def checkMonitorMode(interface):
    """
        Returns true iff the given interface is in Monitor mode.
    """
    output = subprocess.check_output(["iwconfig"]).decode("utf-8").split("\n\n")
    for iface in output:
        if interface in iface and "Mode:Monitor" in iface:
            return True
    return False

class CaptureEngine():
    def __init__(self, interface=None, enableLog=False):
        self.interface = interface
        self.enableLog = enableLog
        self.checkDependencies()
        self.setup()
    
    def setup(self):
        #TODO: Check if the system is using the QCA6174
        applyQca6174Fix()

        if self.interface is not None:
            if not checkMonitorMode(self.interface):
                setMonitorMode(self.interface)
        
        # No given interface, select the first compatible one
        else:
            interfaces = getCompatibleInterfaces()
            if not interfaces:
                print("No compatible interface found. Make sure your wifi card is compatible with Monitor Mode.")

            # Check for monitor mode interfaces
            monitorInterfaces = [name for (name, mode) in interfaces.items() if mode == "Monitor"]
            if monitorInterfaces:
                # Chose first monitor interface 
                interface = monitorInterfaces[0]
            
            # No available monitor interface, configure the first compatible one
            else:
                interface = list(interfaces.keys())[0]
                setMonitorMode(interface)
                interface+="mon"
            
            self.interface = interface
    
    def exitGracefully(self):
        #TODO: reload default driver for QCA6174A 
        disableMonitorMode(self.interface)
        removeQca6174Fix()

    def checkDependencies(self):
        """
            Check if all wifi monitoring dependencies are installed.
            Returns true iff all dependencies are installed, else returns false
        """
        dependencies = ["aircrack-ng", "airodump-ng"]
        for dep in dependencies:
            if programInstalled(dep) is None:
                print(f"Probe Request Capture requires {dep} installed. "
                       f"Please install aircrack-ng using sudo apt-get install aicrack-ng")
                return False
        return True
    
    def startCapture(self):
        #TODO: Find a way to input the captures directly into python as an object (dataframe or other).
        pass        

if __name__ == "__main__":
    if os.getuid() != 0:
        exit("Run as root.")
    
    # Build argument parser
    parser = argparse.ArgumentParser()

    # Set options
    optionGroup = parser.add_argument_group("OPTIONS")
    optionGroup.add_argument("--interface", help="Select an interface to capture on."
                                " If no interface is selected, the first compatible one will be used.",
                                type=str, action="store", dest="interface", default=None)
    optionGroup.add_argument("--enableLogging", help="Select an interface to capture on."
                                " If no interface is selected, the first compatible one will be used.",
                                action="store_true", dest="enableLogging", default=False)
    
    # Parse arguments
    options = parser.parse_args()

    # Create capture engine
    engine = CaptureEngine(options.interface, options.enableLogging)