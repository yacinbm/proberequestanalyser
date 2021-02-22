#!/usr/bin/env python3
"""!
    @file gui.py
    @brief Probe Request Analyzer - GUI

    @author Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    This is a sample application of the captureEngine. It captures probe requests
    from the air and displays them in a GUI. It can filter the captured packets 
    depending on their RSSI value and also read back .pcap files for display.

    Upon clicking Save, a .pcap file and a .csv file are created to save the content
    and the data base is updated. If no database was specified in the browse option 
    menu, then it will be crated on the drive.
"""
VERSION_STRING = "V0.1" #!< Version String

# Native modules
import os
import sys
from hashlib import md5
from datetime import datetime
from shutil import which

# GUI Utility
from tkinter import Tk, Entry, Label, Button, Frame, LEFT, RIGHT, W, E, NORMAL, DISABLED, StringVar, Checkbutton, BooleanVar, OptionMenu, IntVar
from tkinter.ttk import Treeview
from tkinter.filedialog import askopenfilename

# Import top level directory
sys.path.insert(0,'../')

# Import engine components
from source.captureEngine import CaptureEngine
from source.cliColors import bcolors
import source.sqlUtil as sql

# Database Constants
DB_NAME = "../log/captures.db" #!< Name of the local SQLite database
TABLE_NAME = "captures" #!< Name of the SQLite database table

class App:
    """! Graphical User Interface application using Tkinter
    @param master   (Tk tkinter object) Master Tkinter object. 
    """
    def __init__(self, master):
        # Capture engine
        self.__engine = CaptureEngine()
        self.__previousNumCapPkt = 0 # Used to update packet list
        
        # Device Tracking variables
        self.__macAddresses = set()

        # Captured Packet Summary list
        self.packetSummary = []

        ## GUI ##
        self.__master = master
        master.title("Probe Request analyzer")
        
        # Variables
        INTERFACES = self.__engine.getCompatibleInterfaces()
        self.__interface = StringVar(master)
        firstInterface = list(INTERFACES.keys())[0]
        self.__interface.set(firstInterface) # First compatible interface
        self.__filePath = None
        self.__rssiThreshold = IntVar(master)
        self.__rssiThreshold.set(-100)
        self.__numUniqueDevices = IntVar() # Used to identify surrounding devices
        self.__numUniqueDevices.set(f"Unique Devices: {0}")
        
        # Frames 
        self.__settingsFrame = Frame(master)
        self.__packetFrame = Frame(master)
        self.__bottomFrame = Frame(master)
        
        # Labels
        self.__rssiLabel = Label(self.__settingsFrame, text="RSSI Threshold:")
        self.__numUniqueDevicesLabel = Label(self.__settingsFrame, textvariable=self.__numUniqueDevices)

        # Entries       
        self.__rssiEntry = Entry(self.__settingsFrame, textvariable=self.__rssiThreshold)

        # Dropdown menues
        self.__interfaceMenu = OptionMenu(self.__settingsFrame, self.__interface, *INTERFACES)

        # Buttons
        self.__startButton = Button(self.__settingsFrame, 
            text="Start Capture", 
            command=self.startCapture)
        self.__stopButton = Button(self.__settingsFrame, 
            text="Stop Capture", 
            state=DISABLED, 
            command=self.stopCapture)
        self.__browseButton = Button(self.__settingsFrame,
            text="Browse",
            command=self.browse)
        self.__readFileButton = Button(self.__settingsFrame,
            text="Read file",
            command=self.readFile,
            state=DISABLED)
        self.__closeButton = Button(self.__bottomFrame, 
            text="Close", 
            command=self.close)
        self.__saveButton = Button(self.__bottomFrame, 
            text="Save", 
            command=self.save,
            state=DISABLED)
        self.__readDb = Button(self.__settingsFrame, 
            text="Read database")

        # Packet table 
        COLUMNS = [
            "MAC Address Hash",
            "Random MAC",
            "RSSI",
            "SSID",
            "Sequence Number"
        ]
        self.__treeView = Treeview(self.__packetFrame)
        self.__treeView["columns"] = COLUMNS
        self.__treeView["show"] = "headings"
        # Prepare columns
        for col in COLUMNS:
            self.__treeView.heading(col, text=col)
        # Display table
        self.__treeView.grid()

        # Setup the window layout
        # Setting frame
        self.__settingsFrame.grid()
        # Row 0
        self.__rssiLabel.grid(row=0, column=0, sticky=W)
        self.__rssiEntry.grid(row=0, column=1, sticky=W)
        self.__interfaceMenu.grid(row=0, column=2, sticky=W)
        self.__startButton.grid(row=0, column=3, padx=5, pady=5, sticky=E)
        # Row 1
        self.__stopButton.grid(row=1, column=3, padx=5, pady=5,  sticky=E)
        # Row 2
        self.__browseButton.grid(row=2, column=0, sticky=W)
        self.__readFileButton.grid(row=2, column=1, sticky=W)
        self.__numUniqueDevicesLabel.grid(row=2, column=3, sticky=W)

        # Packet Frame
        self.__packetFrame.grid()

        # Bottom Frame
        self.__bottomFrame.grid()
        self.__saveButton.grid(row=0, column=0, padx=5, pady=5)
        self.__closeButton.grid(row=0, column=1, padx=5, pady=5)
        
    # Event handlers
    def close(self):
        """!
        Close the GUI application.
        """
        try:
            self.__engine.exitGracefully()
        finally:
            self.__master.quit()
    
    def save(self, directory=os.path.abspath("../log")):
        """!
        Save the capture data in ../log/. This will output a .csv containing the extracted dataframe,
        a .pcap file containing raw capture data and a .db containing the most relevant data in the 
        captured packets. Note, if a capture.db file already exists, it will be updated with the 
        captured data.
        @param directory    Output directory for the log data.
        """
        # Save pcap
        self.__engine.saveCapFile(directory)
        
        # Save dataframe
        df = self.__engine.buildDataframe(self.__engine.capturedPackets)
        dateTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        fileName = f"dataFrame_{self.__interface.get()}_{dateTime}.csv"
        filePath = os.path.join(directory, fileName)
        df.to_csv(filePath)
        print(f"Saved Captured data dataframe to ../log/{fileName}")

        # Update database
        dbPath = os.path.join(directory, DB_NAME)
        conn = sql.connect(DB_NAME)
        sql.saveDfToDb(conn, TABLE_NAME, df)
        print("Updated the database.")
        
        # Toggle button
        self.__saveButton.config(state=DISABLED)

    def startCapture(self):
        """!
        Start a probe request capture on the selected interface.
        """
        # Capture engine config
        iface = self.__interface.get()
        rssiThreshold = self.__rssiThreshold.get()
        
        try:
            # Update config
            self.__engine.setInterface(iface)
            self.__engine.setRssiThreshold(rssiThreshold)
            # Start capture
            self.__engine.startCapture()
        except Exception as e:
            exit(f"{bcolors.FAIL}Failed to start capture: {e}{bcolors.ENDC}")
        
        # Toggle buttons
        self.__startButton.config(state=DISABLED)
        self.__readFileButton.config(state=DISABLED)
        self.__stopButton.config(state=NORMAL)
        self.__saveButton.config(state=DISABLED)
        
    def stopCapture(self):
        """!
        Stop the capture.
        """
        if not self.__engine:
            # Sanity check
            print(f"{bcolors.FAIL}Engine not degined!{bcolors.ENDC}")
            return

        # Stop Capture
        self.__engine.stopCapture()
        numPackets = len(self.__engine.capturedPackets)
        print(f"Captured {numPackets} packets.")
        
        # Toggle buttons
        self.__startButton.config(state=NORMAL)
        self.__stopButton.config(state=DISABLED)
        self.__saveButton.config(state=NORMAL)
        if self.__filePath:
            self.__readFileButton.config(state=NORMAL)

    def readFile(self):
        """!
        Read the file selected from the browse() function explorer window.
        """
        # Clear packet list
        self.packetSummary = []

        if ".cap" in self.__filePath or ".pcap" in self.__filePath:
            # Add the contents of the cap file to the capture engine.
            self.__engine.readCapFile(self.__filePath)
        
        elif ".db" in self.__filePath:
            # Display the saved summaries in the database
            conn = sql.connect(self.__filePath)
            self.updateSummaries(sql.fetchAll(conn, "captures"))

        else :
            print(f"{bcolors.WARNING}File type not supported!{bcolors.ENDC}")
            self.__filePath = None
        
        # Disable read button after read
        self.__readFileButton.config(state=DISABLED)
        # Enable save
        self.__saveButton.config(state=NORMAL)
    
    def browse(self):
        """!
        Open the file explorer window to select a file to be read. The file can be a .db, .cap or .pcap.
        """
        # Disable read button while browsing
        self.__readFileButton.config(state=DISABLED)
        filename = askopenfilename(initialdir = "~/", 
                                          title = "Select a Capture File", 
                                          filetypes = (("Capture files", 
                                                        ".pcap .cap"), 
                                                        ("SQLite 3 database files",
                                                        ".db"),
                                                       ("all files", 
                                                        "*.*")))

        if filename:
            self.__filePath = filename
            self.__readFileButton.config(state=NORMAL)

    def updateSummaries(self, pktsInfo):
        """!
        Updates the displayed packet summaries table.
        """
        SUMMARY_FIELDS = [
            "sender_addr",
            "random_mac",
            "dBm_AntSignal",
            "ssid",
            "seq_num"
        ]
        for pktInfo in pktsInfo:
            try:
                pktInfo["sender_addr"] = md5(pktInfo["sender_addr"].encode()).hexdigest() # MD5 checksum of the MAC Address
                summary = tuple([pktInfo[field] for field in SUMMARY_FIELDS])
                self.__macAddresses.add(summary[0])
                numUniqueDevices = len(self.__macAddresses)
                self.__numUniqueDevices.set(f"Unique Devices: {numUniqueDevices}")
                self.__treeView.insert("", 'end', values=summary)
            except:
                print(f"{bcolors.WARNING} WARNING - Couldn't fetch the previous packet summary, skipping packet.")
                continue

    def checkNewCap(self):
        """! 
        Checks if new packets have been captured. If there is, call updateSummaries(). This method is called every second.
        """
        if not self.__engine:
            # Sanity check
            return	

        # Check if packets are yet to be displayed
        if self.__previousNumCapPkt < len(self.__engine.capturedPackets):
            missingPkts = self.__engine.capturedPackets[self.__previousNumCapPkt:-1]
            missingPktsInfo = self.__engine.buildDataframe(missingPkts).to_dict('records')

            # Get pkt summary info
            self.updateSummaries(missingPktsInfo)
            
            # Update number of packets
            self.__previousNumCapPkt = len(self.__engine.capturedPackets)
        
        self.__master.after(1000, self.checkNewCap)

def programInstalled(programName):
    """!
    Checks if the program is installed on the current machine.
    @param programName (str) Name of the program.
    @return True iff the program is installed on the machine. 
    """
    return which(programName)

def checkDependencies():
        """!
        Check if all required shell dependencies are installed.
        @return True iff all dependencies are installed.
        """
        dependencies = ["aircrack-ng", "airodump-ng"]
        for dep in dependencies:
            if programInstalled(dep) is None:
                print(f"{bcolors.FAIL}Probe Request Capture requires {dep} installed. "
                       f"Please install aircrack-ng using:\n\tsudo apt-get install aicrack-ng{bcolors.ENDC}")
                return False
        return True

def main():
    """!
    Start the GUI application window.
    """
    root = Tk()
    app = App(root)

    root.after(1000, app.checkNewCap)
    root.mainloop()

if __name__ == "__main__":
    if os.getuid() != 0:
        exit("Run as root.")
    
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
