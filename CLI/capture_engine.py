"""
    Capture Engine module.

    Author: Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    TODO: 
        Create a packet analyser class to seperature packet capture and interpretation.
"""

class CaptureEngine:
    """
        Capture engine component. This is a singleton component, meaning that only one capture engine
        can exist at any time. This is so we can revert back the interface in case of a problem.

        use:
            captureEngine = CaptureEngine(interface="wan0", log=True)
            captureEngine.startCapture()
            [...do stuff here...]
            captureEngine.stopCapture()
            pkts = catureEngine.capturedPackets
            data = captureEngine.extractData(pkts)
            captureEngine.exitGracefully()

        Class arguments:
            interface       -   [String] Interface to do the capture on. Not required if filePath was
                                specified, as the engine will start in offline mode
            filePath        -   [String] Path to the capture file to be read for analysis. Specifying
                                a file path will start the engine in offline mode, which will prevent 
                                user to do capture over the air.
            log             -   [Bool] Specifies if the traffic captured over the air will be saved
                                to the disk in pcap format. The saved data is the raw data captured
                                from Scapy. 

        Class attributes:
            capturedPackets -   [List] List of scapy packets captured by the engine.


        Class methods:
            getInstance()   -   Return the current instance of the CaptureEngine component
            startCapture()  -   Starts a capture on the configured interface. If no interface was selected at
                                creation, it run capture on the first compatible one. The capture is
                                non-blocking, meaning you can start a capture and do other stuff at the same
                                time.
            stopCapture()   -   Stops the capture on the configured interface.
            extractPacketData(pkts)     -   Takes a single packet, or a list of packets, and extracts the 
                                            relenvant Dot11 and Radio tap informations from it. Returns
                                            a list of dictionnaries of information fields by name.
            exitGracefully()    -   Reverts the interface back into managed mode.
    """
    # TODO: Add function to change the class attributes, like interface, log and offlineMode.
    def getInstance():
        """
            Return the capture engine instance.
        """
        if CaptureEngine.__instance == None:
            return CaptureEngine()
        else:
            return CaptureEngine.__instance
    
    __instance = None
    def __init__(self, interface=None, filePath=None, log=False):
        if not CaptureEngine.__instance:
            CaptureEngine.__instance = self
            
            # Attributes
            self.capturedPackets = []
            self.__interface = interface
            self.__log = log
            self.__sniffer = None
            self.__offline = False

            # Initialize the engine
            if not filePath:
                self.__setup()
            else:
                # Run the engine offline from file
                self.__offline = True
                self.capturedPackets = rdpcap(filePath)
        else:
            print(f"{bcolors.WARNING}The CaptureEngine class is a sigleton, please use getInstance() to use the previous instance of the class.{bcolors.ENDC}")
    
    def __setup(self):
        if not checkDependencies():
            exit()
        
        if self.__offline:
            return

        # Setup the interface
        if self.__interface is not None:
            if not self.__checkMonitorMode(self.__interface):
                self.__interface = self.__setMonitorMode(self.__interface)
        
        # No given interface, select the first compatible one
        else:
            interfaces = self.__getCompatibleInterfaces()
            if not interfaces:
                exit(f"{bcolors.FAIL}No compatible interface found. Make sure your wifi card is compatible with Monitor Mode.{bcolors.ENDC}")

            # Check for monitor mode interfaces
            monitorInterfaces = [name for (name, mode) in interfaces.items() if mode == "Monitor"]
            if monitorInterfaces:
                # Select the first compatible one
                interface = monitorInterfaces[0]
            
            # No available monitor interface, configure the first compatible one
            else:
                interface = list(interfaces.keys())[0]
                interface = self.__setMonitorMode(interface)
            
            # Save the interface name
            self.__interface = interface
        
        # Setup the sniffer
        if self.__sniffer is None:
            # Filter received packets to receive only probe req.
            # For more info on the Berkley Packet Filter syntax, 
            # see https://biot.com/capstats/bpf.html
            bpf = "wlan type mgt subtype probe-req"
            self.__sniffer = AsyncSniffer(iface=self.__interface, prn=self.__captureCallback, filter=bpf)
        else:
            pass
    
    def __setMonitorMode(self, interface):
        """
            Set the interface to monitor Mode using airmon-ng.
            This method changes the name of the __interface parameter
        """
        print(f"Setting {interface} in Monitor mode...")
        output = subprocess.call(["sudo", "airmon-ng", "start", interface], stdout=open(os.devnull, 'wb'))
        
        # New interface name
        newInterface = interface + "mon"
        
        if not self.__checkMonitorMode(newInterface) :
            raise RuntimeError(f'Failed to set {interface} in monitor mode! '
                                f'Check if {interface} supports monitor mode with:\n\tiwconfig')
        
        return newInterface

    def __disableMonitorMode(self):
        """
            Set the current 
        """
        interface = self.__interface
        print(f"Setting {interface} back to Managed mode...")
        output = subprocess.call(["sudo", "airmon-ng", "stop", interface], stdout=open(os.devnull, 'wb'))
        if output != 0:
            raise RuntimeError(f'airmon-ng stop {interface} failed!')

    def __getCompatibleInterfaces(self):
        """
            Returns a dict of all compatible interfaces and their current operating mode.
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

    def __checkMonitorMode(self, interface):
        """
            Returns true iff the given interface is in Monitor mode.
        """
        output = subprocess.check_output(["iwconfig"],stderr=open(os.devnull, 'wb')).decode("utf-8").split("\n\n")
        for iface in output:
            if re.search(fr'\b{interface}\b', iface) and "Mode:Monitor" in iface:
                return True
        return False


    def exitGracefully(self):
        """
            Reverts the wireless adapter to managed mode and does a cleanup.
        """
        if not self.__offline:
            self.__disableMonitorMode()
    
    def __captureCallback(self, pkt):
        """
            Packet reception callback function.

            Append the received packet to the capturedPackets list.
        """
        self.capturedPackets.append(pkt)

    def startCapture(self):
        """
            Starts the capture on the engine interface.
        """
        if self.__offline:
            print(f"{bcolors.WARNING}Engine started in offline mode, no capture available.{bcolors.ENDC}")
            return
        
        print("Starting capture...")
        self.__sniffer.start()
        self.__running = True
    
    def stopCapture(self):
        """
            Stops the capture on the sniffer.
        """
        if self.__offline is None:
            print(f"{bcolors.WARNING}Engine started in offline mode, no capture available.{bcolors.ENDC}")
            return
        
        if self.__running:
            print("Stoping capture.")
            self.__sniffer.stop()
        else:
            print("No capture currently running.")

        # Log captured data
        if self.__log:
            dateTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            wrpcap(f"sniffed_{self.__interface}_{dateTime}.pcap", self.capturedPackets)

    def extractPacketData(self,pkts):
        """
            Gets a list of probe request packets and extracts the relevant
            fields. 
            
            Returns a pandas dataFrame containing all the extracted data.
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

    def __isMacRadom(self, addr):
        """
            Checks if Mac address is random. 
            Return True if random, else returns False.
        """
        byteList = ['2', '3', '6', '7',  'a', 'b',  'e', 'f']
        secondByte = addr[1]
        if secondByte in byteList:
            return True
        else:
            return False

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
            i.e. the information for element ID 221 is "info21" and the data is
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
        
        # Mac address randomisation
        dataDict["random_mac"] = self.__isMacRadom(dataDict["sender_addr"])

        # Device Manufacturer name
        dataDict["manufacturer"] = self.__getManufacturerName(dataDict["sender_addr"])

        # Sequence Number
        SC = pkt.SC
        hexSC = '0' * (4 - len(hex(SC)[2:])) + hex(SC)[2:]
        dataDict["seq_num"] = int(hexSC[:-1],16)

        # Dot11 Flags
        dataDict.update(self.__extractFlags(pkt.FCfield))

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

                # Check if value is overflow two big to be an int, if it is, reprensent as str
                if type(value) == int and value > sys.maxsize:
                    value = str(value)

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
                    dataDict.update(self.__extractFlags(pkt.FCfield))
                    continue
                
                # Field already exists
                if name in dataDict:
                    dataDict[name] = dataDict[name] + value
                else:
                    dataDict[name] = value

            # Get next dot11 element
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        
        return dataDict

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