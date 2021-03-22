"""!
    @file captureEngine.py
    @brief Capture Engine module.

    @author Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    TODO:
        *   Create a packet analyzer class to seperature packet capture and interpretation.
        *   Create a class for instances instead of having just a string
            and manage the setup from within that class.
"""
import sys
from datetime import datetime
from pathlib import Path
from scapy.all import wrpcap, rdpcap, AsyncSniffer, RadioTap, scapy, Dot11, Dot11Elt, Dot11ProbeReq
import pandas as pd
from netaddr import EUI

from .cliColors import bcolors # Colored prints

class CaptureEngine:
    """! @brief Capture engine component. 
    
        The capture engine component is used to handle of the data aquisition for wifi packets.
        It sets a monitor compatible interface into monitor mode and can start sniffing for 
        wifi traffic. The captured packets can be filtered using the bpFilter attribute and the 
        rssiThreshold attribute. The captured packets are then stored in the capturedPacktes public
        attribute of the engine. The data they contain can be extracted into a pandas dataframe
        using the CaptureEngine.buildDataFrame method on the list for better readability and analysis.
        
        This is a singleton component, meaning that only one capture engine
        can exist at any time. This is so we can revert back the interface in case of a problem.

        use:
        @code{.py}
            captureEngine = CaptureEngine(interface="wan0")
            captureEngine.startCapture()
            [...do stuff here...]
            captureEngine.stopCapture()
            # Save raw cap file
            captureEngine.saveCapFile("../log/")
            pkts = catureEngine.capturedPackets
            data = captureEngine.buildDataframe(pkts)
            captureEngine.exitGracefully()
        @endcode
    """
    # Variable to insure singleton
    __instance = None
    def __init__(self, interface, bpFilter=None, rssiThreshold=float("-inf")):
        """! @brief The constructor.
        @param self The capture engine pointer.
        @param interface    \b str Interface to do the capture on. If no interface is specified, the engine will detect the first
                            compatible one and use it.
        @param bpFilter     [Optional]\b str Berkley Packet Filter to determine what packets are to be captured. For more info, 
                            see https://biot.com/capstats/bpf.html. By default, the engine only capture probe requests.
        @param rssiThreshold    [Optional]\b numerical Received Signal Strength Indicator (RSSI) capture threshold. If the captured packet has a 
                                lower RSSI than the one specified, it will be ignored. If no rssiThreshold is given, all packets will
                                be captured, regardless of their RSSI value.
        """
        if not CaptureEngine.__instance:
            # Save singleton instance
            CaptureEngine.__instance = self
            
            # Public Attributes
            ## \b list List of captured packets over the air, or read from a file.
            self.capturedPackets = []

            # Private Attributes
            self.__interface = interface
            self.__running = False
            self.__filter = "wlan type mgt subtype probe-req" if bpFilter is None else bpFilter
            self.__rssiThreshold = rssiThreshold
            self.__sniffer = AsyncSniffer(iface=self.__interface, prn=self.__captureCallback, filter=self.__filter)

        else:
            print(f"{bcolors.WARNING}The CaptureEngine class is a sigleton, please use getInstance() to use the previous instance of the class.{bcolors.ENDC}")

    def clearCapturedData(self):
        """!
            @brief Clears the list of packet data.
        """
        self.capturedPackets = []

    def getInstance():
        """! @brief Returns the capture engine instance.

        Example Use:
        @code{.py}
        myCaptureEngine = CaptureEngine()
        [...do stuff...]
        myCaptureEngineReference = CaptureEngine.getInstance()
        @endcode
        @return Returns the current CaptureEngine instance. If no instance exists, returns a new instance.
        """
        if CaptureEngine.__instance == None:
            return CaptureEngine(None)
        else:
            return CaptureEngine.__instance
    
    def getInterface(self):
        """! @brief Returns the interface name.
            @return \b str Interface name.
        """
        return self.__interface
    
    def __captureCallback(self, pkt):
        """
            Packet reception callback function.

            Append the received packet to the capturedPackets list.
        """
        try:
            # Check RSSI threshold and save
            radioTapElt = pkt.getlayer(RadioTap)
            rssi = getattr(radioTapElt, "dBm_AntSignal")
            if rssi >= self.__rssiThreshold:
                self.capturedPackets.append(pkt)
        except:
            # Exception handling
            pass
    
    def setInterface(self, interface):
        """! @brief Changes the interface.
        @param self The capture engine pointer.
        @param interface \b str Name of the interface to use.
        Example use:
        @code{.py}
        myCaptureEngine = CaptureEngine()
        interface = "wlan0"
        myCaptureEngine.setInterface(interface)
        @endcode
        """
        # Check input param
        if type(interface) is not str:
            print(f"{bcolors.WARNING}interface should be a string.{bcolors.ENDC}")
        
        # Check if engine running
        if self.__running:
            print(f"{bcolors.WARNING}Please stop the engine before changing parameters.{bcolors.ENDC}")
            return

        # Update interface and sniffer
        self.__interface = interface
        self.__sniffer = AsyncSniffer(iface=self.__interface, prn=self.__captureCallback, filter=self.__filter)

    
    def setRssiThreshold(self, rssiThreshold):
        """! @brief Sets the RSSI threshold filter. Packets with a lower RSSI then the threshold will be ignored.
        @param self The capture engine pointer.
        @param rssiThreshold    The Received Signal Strength (RSSI) threshold in dBm.
        Example use:
        @code{.py}
        myCaptureEngine = CaptureEngine()
        rssiThreshold = -65
        myCaptureEngine.setRssiThreshold(rssiThreshold)
        @endcode
        """
        # Check if engine running
        if self.__running:
            print(f"{bcolors.WARNING}Please stop the engine before changing parameters.{bcolors.ENDC}")
            return

        # Update interface
        self.__rssiThreshold = rssiThreshold

    def readCapFile(self, filePath):
        """! @brief Reads the capture file and appends the packets to the captured packets list.
        @param self The capture engine pointer.
        @param filePath \b str Path to the capture file to be read.
        Example use:
        @code{.py}
        myCaptureEngine = CaptureEngine()
        capFilePath = "./mycapfile.cap"
        myCaptureEngine.readCapFile(capFilePath)
        # Build a dataframe from the read data
        capturedDataFrame = myCaptureEngine.buildDataframe()
        @endcode
        """
        # TODO: Should we just return a list of packets instead of appending it to the list of captured packets?
        # Check input param
        if type(filePath) != str:
            print(f"{bcolors.WARNING}filePath should be a string.{bcolors.ENDC}")
            return
        
        # Check if engine running
        if self.__running:
            print(f"{bcolors.WARNING}Please stop the engine before reading files.{bcolors.ENDC}")
            return
        
        # Read cap file 
        pkts = rdpcap(filePath)
        self.capturedPackets.extend([pkt for pkt in pkts])
        print(f"Read {len(pkts)} packets.")

    def startCapture(self):
        """! @brief Starts the packet capture. 
        This method is asynchronous, meaning that it is non-blocking. The capture will keep going
        until the stopCapture() method is called.
        @param self The capture engine pointer.
        Example use:
        @code{.py}
        myCaptureEngine = CaptureEngine()
        myCaptureEngine.startCapture()
        [...keep doing stuff here...]
        myCaptureEngine.stopCapture()
        @endcode
        """
        print("Starting capture...")
        self.__sniffer.start()
        self.__running = True
    
    def stopCapture(self):
        """! @brief Stops the packet capture.
        @param self The capture engine pointer.
        Example use:
        @code{.py}
        myCaptureEngine = CaptureEngine()
        myCaptureEngine.startCapture()
        [...keep doing stuff here...]
        myCaptureEngine.stopCapture()
        @endcode
        """
        if self.__running:
            print("Stoping capture.")
            self.__sniffer.stop()
            self.__running = False
        else:
            print(f"{bcolors.WARNING}No capture currently running.{bcolors.ENDC}")

    def saveCapFile(self, pkts):
        """! @brief Saves the currently captured packets to a pcap log file to the given directory. 
        The log file contains raw scapy captures and is named with date time, as well as 
        the interface where it was captured on.
        @param self The capture engine pointer.
        @para pkts Raw scapy packets to be saved to the .pcap file.
        """
        # Create output folder if missing
        logDir = Path(__file__).parent/"log"
        logDir.mkdir(parents=True, exist_ok=True)
        
        # Save .pcap file
        dateTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        fileName = f"sniffed_{self.__interface}_{dateTime}.pcap"
        filePath = str(logDir/fileName)
        wrpcap(filePath, pkts)

        print(f"{bcolors.OKGREEN}Saved capfile to {filePath}{bcolors.ENDC}")

    def buildDataframe(self,pkts):
        """! @brief Builds a pandas dataframe from the given scapy packets list. 
        The data fields are Dot11 (see 802.11 standard for more details),
        and RadioTap fields (see https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html#scapy.layers.dot11.RadioTap
        for more details)
        @param self The capture engine pointer.
        @param pkts \b list List of scapy packets containing data to be extracted
        @return Returns a Pandas Dataframe containing the extracted data from the packets list.
        """
        listDict = []

        for pkt in pkts:
            # Radio Tap Fields extraction
            try:
                radioTapDict = self.__getRadioTapFields(pkt)
            except Exception as e:
                print(f"Warning - {bcolors.WARNING}{e}: Error getting radio tap data, skipping packet.{bcolors.ENDC}")
                continue
            
            # Dot11 Elements extraction
            try:
                dot11Dict = self.__getDot11Fields(pkt)
            except Exception as e:
                print(f"Warning - {bcolors.WARNING}{e}: Error getting dot11 data, skipping packet.{bcolors.ENDC}")
                continue

            listDict.append({**radioTapDict, **dot11Dict})

        # Output dataframe
        return pd.DataFrame.from_dict(listDict).astype(str)

    def __getRadioTapFields(self, pkt):
        """
            This function iterates through all the received Radio Tap fields in the
            packet. 
            
            Returns a dictionary of values by field name.
        """
        dataDict = {}

        # Check if the packet is a valid Dot11 packet
        if not pkt.haslayer(RadioTap):
            print(f"{bcolors.WARNING}Packet has no radio tap layer.{bcolors.ENDC}")
            return None
        
        ignoredFields = ["notdecoded", "Ext"]

        radioTapElt = pkt.getlayer(RadioTap)
        for field in filter(lambda el: el not in ignoredFields, radioTapElt.fields):
            name = field
            value = getattr(radioTapElt, field)

            # Check if value is overflow two big to be an int, if it is, reprensent as str
            if type(value) == int and value > sys.maxsize:
                value = str(value)

            # Handle flags
            if type(value) == scapy.fields.FlagValue:
                dataDict.update(self.__extractFlags(pkt.FCfield))
                continue
            
            # Field already exists
            if name in dataDict:
                dataDict[name] = dataDict[name] + value
            else:
                dataDict[name] = value
        
        return dataDict
    
    def __getDot11Fields(self, pkt):
        """
            This function iterates through all the received Dot11 elements in the
            packet. 
            Returns a dictionary of values by field name.

            Returns None if the packet doesn't contain a Dot11 layer.
            
            The "other" dot11 elements are elements that were not implemented 
            natively by Scapy. Here, we simply read those fields and present them
            in a usable format with their ID appended to the info field name,
            i.e. the information for element ID 21 is "info21" and the data is
            simply the binary string received.

            For more information on the IDs of the elements and their meaning, see 
            https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html
        """
        dataDict = {}

        # Check if the packet is a valid Dot11 packet
        if not pkt.haslayer(Dot11):
            print(f"{bcolors.WARNING}Packet has no Dot11 layer.{bcolors.ENDC}")
            return None

        # Get the Dot11 parameters of the packet
        # MAC addresses
        dataDict["receiver_addr"] = pkt.addr1
        dataDict["sender_addr"] = pkt.addr2
        dataDict["bssid"] = pkt.addr3
        dataDict["random_mac"] = self.__isMacRadom(dataDict["sender_addr"])

        # Device Manufacturer name
        dataDict["manufacturer"] = self.__getManufacturerName(dataDict["sender_addr"])

        # Sequence Number
        SC = pkt.SC
        if SC:
            hexSC = '0' * (4 - len(hex(SC)[2:])) + hex(SC)[2:]
            dataDict["seq_num"] = int(hexSC[:-1],16)
        else:
            dataDict["seq_num"] = None

        # Default SSID value
        dataDict["ssid"] = b""

        # Dot11 Flags
        dataDict.update(self.__extractFlags(pkt.FCfield))

        # Dot11 Elements
        # Iterate through all the payloads of the packet and extract everyting
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

                if type(value) == int and value > sys.maxsize:
                    # Value too big for int, reprensent as str
                    value = str(value)

                # Handle Element flags
                if type(value) == scapy.fields.FlagValue:
                    dataDict.update(self.__extractFlags(pkt.FCfield))
                    continue
                
                if name not in dataDict:
                    dataDict[name] = value
                # Data field exists in the dict
                else:
                    dataDict[name] += value

            # Get next dot11 element
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        
        return dataDict

    def __isMacRadom(self, addr):
        """
            Checks if Mac address is random. 
            Return True if random, else returns False.
        """
        if not addr:
            # Sanity check
            return False

        byteList = ['2', '3', '6', '7',  'a', 'b',  'e', 'f']
        secondByte = addr[1]
        if secondByte in byteList:
            return True
        else:
            return False

    def __extractFlags(self, flags):
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

    def __getManufacturerName(self, addr):
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