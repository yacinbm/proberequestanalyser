"""!
    @file wifiUtil.py
    @brief Utilities to configure the wifi interfaces.

    @author Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    These utilities should be used to get/set the wifi interface operating mode,
"""
import os
import subprocess # Executing external processes
import re
from .cliColors import bcolors

def getMonCompatIfaces():
    """! @brief Get a dict of all compatible interfaces and their current operating mode.
    Example Use:
    @code{.py}
    compatibleInterfaces = getMonCompatIfaces()
    #Change the interface to the first compatible one
    interfaceName = list(compatibleInterfaces.keys())[0]
    @endcode
    @return Returns dict of all compatible interfaces and their current operating mode.
    """
    output = subprocess.check_output(["iwconfig"],stderr=open(os.devnull, 'wb')).decode("utf-8").split("\n\n")
    output = list(filter(None, output)) # Remove empty strings
    if not output:
        exit(f"{bcolors.FAIL}No compatible interface found. Make sure your wifi card supports Monitor mode.{bcolors.ENDC}")
    
    interfaceDict = {}
    for interface in output:
        name = interface.split(" ")[0]
        mode = interface.split("Mode:")[1].split(" ")[0]
        interfaceDict[name] = mode
    return interfaceDict

def setManagedMode(interface):
    """! @brief Sets the given interface to managed mode.
        @param interface \b str Name of the interface.
        @return Returns the name of the new managed mode interface.
    """
    print(f"Setting {interface} back to Managed mode...")
    output = subprocess.call(["sudo", "airmon-ng", "stop", interface], stdout=open(os.devnull, 'wb'))
    if output != 0:
        raise RuntimeError(f'{bcolors.FAIL}airmon-ng stop {interface} failed! {interface} may need to be set to managed mode manually.')

def isMonitorMode(interface):
    """! @brief Checks if the interface is in monitor mode.
        @return Returns true iff the given interface is in Monitor mode.
    """
    output = subprocess.check_output(["iwconfig"],stderr=open(os.devnull, 'wb')).decode("utf-8").split("\n\n")
    for iface in output:
        if re.search(fr'\b{interface}\b', iface) and "Mode:Monitor" in iface:
            return True
    return False

def setMonitorMode(interface):
    """! @brief Set the interface to monitor Mode.
        @return Returns the name of the new monitor mode interface.
    """
    print(f"Setting {interface} in Monitor mode...")
    output = subprocess.call(["sudo", "airmon-ng", "start", interface], stdout=open(os.devnull, 'wb'))
    
    # New interface name
    newInterface = interface + "mon"
    
    if not isMonitorMode(newInterface) :
        raise RuntimeError(f'{bcolors.FAIL}Failed to set {interface} in monitor mode! '
                            f'Check if {interface} supports monitor mode with:\n\tiwconfig{bcolors.ENDC}')
    
    return newInterface

def setupIface(interface=None):
    """!
        @brief Sets up a monitor compatible wifi interface for probe request capture
        @param interface [Optional]\b str Name of the interface to setup.
        @return \b str Returns the name of the configured interface. 
    """
    # Interface was given
    if interface is not None:
        # Check if interface is compatible
        if interface not in getMonCompatIfaces():
            print(f"{bcolors.FAIL}{interface} does not support monitor mode.{bcolors.ENDC}")
            return None
        
        # Check if interface is already in monitor mode
        if not isMonitorMode(interface):
            outputInterface = setMonitorMode(interface)
        # Interface is already in monitor mode
        else:
            outputInterface = interface
    
    # No given interface, select the first compatible one
    else:
        compatibleInterfaces = getMonCompatIfaces()
        if not compatibleInterfaces:
            exit(f"{bcolors.FAIL}No compatible interface found. Make sure your wifi card is compatible with Monitor Mode.{bcolors.ENDC}")

        # Check for monitor mode interfaces
        monitorInterfaces = [name for (name, mode) in compatibleInterfaces.items() if mode == "Monitor"]
        if monitorInterfaces:
            # Select the first compatible one
            outputInterface = monitorInterfaces[0]
        
        # No available monitor interface, configure the first compatible one
        else:
            interface = list(compatibleInterfaces.keys())[0]
            outputInterface = setMonitorMode(interface)

    return outputInterface