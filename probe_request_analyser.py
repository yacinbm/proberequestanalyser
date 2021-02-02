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
    Capture probe requests using airodump-ng
        - Create a structure to organize the requests per client (dict or data frame)
            * Have an input parameter that allows for saving the stucture
        - Filter the received request with a variable RSSI value
            * Have an input parameter that changes the threshold
        - Analyze the probe requests (sample function)
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

# External modules
try:
    from scapy.all import *
except ImportError:
    exit("Scapy is required for this application, please install with"
            "\npip install scapy")

try:
    from netaddr import *
except ImportError:
    exit("Netaddr is required for this application, please install with"
            "\npip install netaddr")

try:
    import pandas as pd
except ImportError:
    exit("Pandas is required for this application, please install with"
            "\npip install pyshark")


def programInstalled(programName):
    """
        Return true iff the program is installed on the machine.
    """
    return which(programName)

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
    print(f"Setting {interface} back to Managed mode...")
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

def checkDependencies():
        """
            Check if all wifi monitoring dependencies are installed.
            Returns true iff all dependencies are installed, else returns false
        """
        dependencies = ["aircrack-ng", "airodump-ng"]
        for dep in dependencies:
            if programInstalled(dep) is None:
                print(f"Probe Request Capture requires {dep} installed. "
                       f"Please install aircrack-ng using \nsudo apt-get install aicrack-ng")
                return False
        return True

class CaptureEngine():
    # TODO: Add functionnality to read from .pcap file
    def __init__(self, interface=None, filePath=None, log=False):
        # Attributes
        self.interface = interface
        self.log = log
        self.sniffer = None
        self.capturedPackets = []
        self.offline = False

        # Initialize the engine
        if not filePath:
            self._setup()
        else:
            # Run the engine offline from file
            self.offline = True
            self.capturedPackets = rdpcap(filePath)
    
    def _setup(self):
        if not checkDependencies():
            exit()

        # Setup the interface
        if self.interface is not None:
            if not checkMonitorMode(self.interface):
                setMonitorMode(self.interface)
        
        # No given interface, select the first compatible one
        else:
            interfaces = getCompatibleInterfaces()
            if not interfaces:
                exit("No compatible interface found. Make sure your wifi card is compatible with Monitor Mode.")

            # Check for monitor mode interfaces
            monitorInterfaces = [name for (name, mode) in interfaces.items() if mode == "Monitor"]
            if monitorInterfaces:
                interface = monitorInterfaces[0]
            
            # No available monitor interface, configure the first compatible one
            else:
                interface = list(interfaces.keys())[0]
                setMonitorMode(interface)
                # Monitor interface name
                interface+="mon" 
            
            # Save the interface name
            self.interface = interface
        
        # Setup the sniffer
        if self.sniffer is None:
            # Filter received packets to receive only probe req.
            # For more info on the Berkley Packet Filter syntax, 
            # see https://biot.com/capstats/bpf.html
            bpf = "wlan type mgt subtype probe-req"
            self.sniffer = AsyncSniffer(iface=self.interface, prn=self.captureCallback, filter=bpf)
        else:
            pass

    def exitGracefully(self):
        """
            Reverts the wireless adapter to managed mode and does a cleanup.
        """
        if not self.offline:
            disableMonitorMode(self.interface)
    
    def captureCallback(self, pkt):
        """
            Packet reception callback function.

            Append the received packet to the capturedPackets list.
        """
        self.capturedPackets.append(pkt)

    def startCapture(self):
        """
            Starts the capture on the engine interface.
        """
        if self.sniffer is None:
            print("Engine started in offline mode, no capture available.")
            return
        
        print("Starting capture...")
        self.sniffer.start()
    
    def stopCapture(self):
        """
            Stops the capture on the sniffer.
        """
        if self.sniffer is None:
            print("Engine started in offline mode, no capture available.")
            return
        
        print("Stoping capture.")
        self.sniffer.stop()

        # Log captured data
        if self.log:
            dateTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            wrpcap(f"sniffed_{self.interface}_{dateTime}.pcap", self.capturedPackets)

    def extractPacketData(self,pkts):
        """
            Gets a list of probe request packets and extracts the relevant
            fields. 
            
            Returns a pandas dataFrame containing all the extracted data.
        """
        from IPython.display import display
        df = pd.DataFrame()
        for pkt in pkts:
            dataDict = {}
            # Radio Tap Fields extraction
            #dataDict.update(self.getRadioTapFields(pkt))
            
            # Dot11 Elements extraction
            dataDict.update(self.getDot11Fields(pkt))
            
            df = df.append(dataDict, ignore_index=True)
        
        return df

    def getRadioTapFields(self, pkt):
        """
            
        """
        pass

    def getDot11Fields(self, pkt):
        """
            This function iterates through all the received Dot11 elements in the
            packet. 
            Returns a dictionary of values by field name.

            Returns None if the packet doesn't contain a Dot11 layer.
            
            The "other" dot11 elements are elements that were not implemented 
            natively by Scapy. Here, we simply read those fields and present them
            in a usable format with their ID appended to the info field name,
            i.e. the information for element ID 221 is "info21" and the data is
            simply the binary string received.

            For more information on the IDs of the elements and their meaning, see 
            https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html
        """
        # Iterate through all the Dot11 elements
        dataDict = {}

        # Check if the packet is a valid Dot11 packet
        if not pkt.haslayer(Dot11):
            return None

        # Get the Dot11 parameters of the packet
        # MAC addresses
        dataDict["receiverAddr"] = pkt.addr1
        dataDict["senderAddr"] = pkt.addr2
        dataDict["bssid"] = pkt.addr3

        # Device Manufacturer name
        dataDict["manufacturer"] = self.getManufacturerName(dataDict["senderAddr"])

        # Sequence Number
        SC = pkt.SC
        hexSC = '0' * (4 - len(hex(SC)[2:])) + hex(SC)[2:]
        dataDict["seqNum"] = int(hexSC[:-1],16)

        # Dot11 Flags
        dataDict.update(self.extractFlags(pkt.FCfield))

        # Dot11 Elements
        dot11elt = pkt.getlayer(Dot11Elt)
        while dot11elt:
            ignoredFields = [
                "ID",
                "len"
            ]
            # Iterate through all the fields in the element
            for field in filter(lambda el: el not in ignoredFields, dot11elt.fields):
                name = field
                value = getattr(dot11elt, field)
                # Elements not decoded by Scapy contain an "info" field. 
                # Add the element ID to differentiate them.
                if field == "info":
                    if dot11elt.ID == 0:
                        # SSID
                        name = "ssid"
                    else:
                        # TODO: Implement decoding for relevant fields, if necessary
                        name = field + str(dot11elt.ID)

                # Handle Element flags
                if type(value) == scapy.fields.FlagValue:
                    dataDict.update(self.extractFlags(pkt.FCfield))
                    continue
                
                # Field already exists
                if name in dataDict:
                    dataDict[name] = list(dataDict[name]) + value
                else:
                    dataDict[name] = value

            # Get next dot11 element
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        return dataDict

    def extractFlags(self, flags):
        """
            Gets a scapy flag type and returns a dictionnary of flag values by flag names.

            The Scapy flag type is a list of flag names along with an int concatenating 
            all the binary values for the flags.
        """
        flagsDict = {}
        values = flags.value
        for i, name in enumerate(flags.names):
            # Get the bit value 
            flagsDict[name] = values >> i & 1
        
        return flagsDict

    def getManufacturerName(self, addr):
        """ 
            Returns the name of the organisation associated to the given MAC.
            If no organisation is listed for that MAC, returns None
        """
        try:
            manuf = EUI(str(addr)).oui.registration().org
        except :
            # Sometimes the organisation is not registered for some reason
            manuf = None
        return manuf

def _buildParser():
    parser = argparse.ArgumentParser()

    # Set options
    optionGroup = parser.add_argument_group("OPTIONS")
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
    # Build the argument parser
    parser = _buildParser()
    
    # Parse arguments
    options = parser.parse_args()
    
     # Create capture engine
    engine = CaptureEngine(options.interface, filePath=options.filePath, log=options.log)
    engine.startCapture()
    
    # Capture until we catch a packet
    while len(engine.capturedPackets) < 10:
        continue
    
    engine.stopCapture()
    pkts = engine.capturedPackets
    dct = engine.extractPacketData(pkts)
    pd.DataFrame(dct).to_csv("outuput.csv")
    engine.exitGracefully()

if __name__ == "__main__":
    if os.getuid() != 0:
        exit("Run as root.")
    
    # Keyboard Interrupt handleing
    try:
        main()
    except KeyboardInterrupt:
        try:
            engine.exitGracefully()
        except NameError:
            os._exit(0)