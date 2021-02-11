#!/usr/bin/env python3
"""
    Probe Request Analyser - CLI

    Author: Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

    This is a sample application of the captureEngine. It captures probe requests
    from the air and displays them in a GUI. It can filter the captured packets 
    depending on their RSSI value and also read back .pcap files for display.
"""
import os
import sys
from shutil import which

from tkinter import Tk, Entry, Label, Button, Frame, LEFT, RIGHT, W, E, NORMAL, DISABLED, StringVar, Checkbutton, BooleanVar, OptionMenu, IntVar
from tkinter.ttk import Treeview
from tkinter.filedialog import askopenfilename
from datetime import datetime
from source.captureEngine import CaptureEngine
from source.cliColors import bcolors

class App:
    def __init__(self, master):
        # Capture engine
        self.engine = CaptureEngine()

        # Captured Packet Summary list
        self.packetSummary = []

        ## GUI ##
        self.master = master
        master.title("Probe Request Analyser")
        
        # Variables
        INTERFACES = self.engine.getCompatibleInterfaces()
        self.interface = StringVar(master)
        firstInterface = list(INTERFACES.keys())[0]
        self.interface.set(firstInterface) # First compatible interface
        self.filePath = None
        self.rssiThreshold = IntVar(master)
        self.rssiThreshold.set(-100)
        self.log = BooleanVar(master)
        self.log.set(False)
        
        # Frames 
        self.__settingsFrame = Frame(master)
        self.__packetFrame = Frame(master)
        self.__bottomFrame = Frame(master)
        
        # Labels
        self.__rssiLabel = Label(self.__settingsFrame, text="RSSI Threshold:")

        # Entries       
        self.__rssiEntry = Entry(self.__settingsFrame, textvariable=self.rssiThreshold)

        # Dropdown menues
        self.__interfaceMenu = OptionMenu(self.__settingsFrame, self.interface, *INTERFACES)

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
            command=self.readCapFile,
            state=DISABLED)
        self.__closeButton = Button(self.__bottomFrame, 
            text="Close", 
            command=self.close)
        self.__saveButton = Button(self.__bottomFrame, 
            text="Save", 
            command=self.save,
            state=DISABLED)

        # Packet table 
        COLUMNS = [
            "MAC Address",
            "Random MAC",
            "RSSI",
            "SSID",
            "Sequence Number"
        ]
        self.treeView = Treeview(self.__packetFrame)
        self.treeView["columns"] = COLUMNS
        self.treeView["show"] = "headings"
        # Prepare columns
        for col in COLUMNS:
            self.treeView.heading(col, text=col)
        # Display table
        self.treeView.grid()

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

        # Packet Frame
        self.__packetFrame.grid()

        # Bottom Frame
        self.__bottomFrame.grid()
        self.__saveButton.grid(row=0, column=0, padx=5, pady=5)
        self.__closeButton.grid(row=0, column=1, padx=5, pady=5)
        
    # Event handlers
    def close(self):
        try:
            self.engine.exitGracefully()
        finally:
            self.master.quit()
    
    def save(self):
        # Save pcap
        self.engine.saveData()
        
        # Save dataframe
        df = self.engine.getDataFrame(self.engine.capturedPackets)
        dateTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        fileName = f"dataFrame_{self.interface.get()}_{dateTime}.csv"
        dirName = os.path.dirname(__file__)
        filePath = os.path.join(dirName, f"./log/{fileName}")
        df.to_csv(f"{filePath}")
        print(f"Saved dataframe to log/{fileName}")
        self.__saveButton.config(state=DISABLED)

    def startCapture(self):
        # Capture engine config
        log = self.log.get()
        iface = self.interface.get()
        
        try:
            # Update config
            self.engine.setInterface(iface)
            self.engine.setLogging(log)
            # Start capture
            self.engine.startCapture()
        except Exception as e:
            exit(f"{bcolors.FAIL}Failed to start capture: {e}{bcolors.ENDC}")
        
        # Toggle buttons
        self.__startButton.config(state=DISABLED)
        self.__readFileButton.config(state=DISABLED)
        self.__stopButton.config(state=NORMAL)
        self.__saveButton.config(state=DISABLED)
        
    def stopCapture(self):
        """
            Stops capture and deletes the old capture engine. Also reverts the interface back to managed mode.
        """
        if not self.engine:
            # Sanity check
            print(f"{bcolors.FAIL}Engine not degined!{bcolors.ENDC}")
            return

        # Stop Capture
        self.engine.stopCapture()
        numPackets = len(self.engine.capturedPackets)
        print(f"Captured {numPackets} packets.")
        
        # Toggle buttons
        self.__startButton.config(state=NORMAL)
        self.__stopButton.config(state=DISABLED)
        self.__saveButton.config(state=NORMAL)
        if self.filePath:
            self.__readFileButton.config(state=NORMAL)

    def readCapFile(self):
        # Clear packet list
        self.packetSummary = []
        # Set file path and read file
        self.engine.readFile(self.filePath)
        # Disable read button after read
        self.__readFileButton.config(state=DISABLED)
        # Enable save
        self.__saveButton.config(state=NORMAL)
    
    def browse(self):
        # Disable read button while browsing
        self.__readFileButton.config(state=DISABLED)
        filename = askopenfilename(initialdir = "~/", 
                                          title = "Select a Capture File", 
                                          filetypes = (("Capture files", 
                                                        ".pcap .cap"), 
                                                       ("all files", 
                                                        "*.*")))

        if filename:
            self.filePath = filename
            self.__readFileButton.config(state=NORMAL)

    def updatePacketList(self):
        """
            Updates the list of packets to be displayed.
        """
        if not self.engine:
            # Sanity check
            return	

        pktListSize = len(self.packetSummary)
        if pktListSize != len(self.engine.capturedPackets):
            missingPkts = self.engine.capturedPackets[pktListSize:-1]
            missingPktsInfo = self.engine.getDataFrame(missingPkts).to_dict('records')

            for pktInfo in missingPktsInfo:
                rssi = pktInfo["dBm_AntSignal"]
                if int(rssi) < self.rssiThreshold.get():
                    continue
                mac = pktInfo["sender_addr"]
                randomMac = pktInfo["random_mac"]
                ssid = pktInfo["ssid"] if pktInfo["ssid"] else None
                seqNum = pktInfo["seq_num"]
                summary = (mac, randomMac, rssi, ssid, seqNum)
                self.packetSummary.append(summary)
                self.treeView.insert("", 'end', values=summary)
        
        self.master.after(1000, self.updatePacketList)

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

def main():
    root = Tk()
    app = App(root)

    root.after(1000, app.updatePacketList)
    root.mainloop()

if __name__ == "__main__":
    if os.getuid() != 0:
        exit("Run as root.")
    
    # Keyboard Interrupt handleing
    try:
        checkDependencies()
        main()
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR - {e}\nCleaning up...{bcolors.ENDC}")
        try:
            engine = CaptureEngine.getInstance()
            engine.exitGracefully()
        except:
            os._exit(0)
