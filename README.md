# Introduction 
This application aims to capture and extract relevant features of probe requests using a monitor mode compatilble Wi-Fi card.
It revolves around a central CaptureEngine component which is charged with setting up the wireless interface and capturing 
probe requests using the Scapy python library. It is also used to extract relevant Dot11 and RadioTap fields which are relevant to 
analyze the probe requests and their emittor. 

This repository contrains two demo applications indicating how to use the CaptureEngine component. The first one is a command line interface,
and the second one is a Graphical User Interface with more advanced functionnality.

# Getting Started
1.	Installation process
If you're using the Jetson Nano with the QCA6174A wifi card, please follow the next section, otherwise you can skip it.
## QCA6174A INSTALLATION

When using this program with the QCA6174A, you need to install a custom firmware that supports rawmode and cryptmode. 

You can use the firmware found at https://github.com/kvalo/ath10k-firmware/raw/master/QCA6174/hw3.0/4.4.1.c3/firmware-6.bin_WLAN.RM.4.4.1.c3-00075.

Download the firmware file and rename it to firmware-2.bin. Now to install the firmware:

* Back up the original firmware for your machine:
```bash
cd /lib/firmware/ath10k/QCA6174
sudo cp -r hw[hw_version] hw[hw_version]_ori
```
* Remove the old firmware files:
```bash
 sudo rm /hw[hw_version]/firmware-*.bin
```
(Note, the card used in the buspas module is hw3.0)
* Copy the new firmware file:
```bash
sudo cp /path/to/fw_file/[your firmware] ./firmware-2.bin
```

Now in order to use a more recent firmware, you need to use a recent driver. For this, we use backports. Download backport v5.3.6-1 from https://cdn.kernel.org/pub/linux/kernel/projects/backports/stable/ and extract it. In the backports folder, execute the following commands to build the ath10k driver:
```bash
make defconfig-ath10k
make -j4
sudo make install
```
Finally, create a driver configuration file under /etc/modprobe.d/ath10k_core.conf containing the following lines:
```
options ath10k_core rawmode=1
options ath10k_core cryptmode=1
```
Now reboot your system to make sure the wlan interface is still showing with ifconfig.

2.	Software dependencies
The application requires Python3. Make sure it is installed on your system. 
Otherwise, you can install it with:
```
sudo apt-get install python3, python3-pip
```
Firs off, install airmon-ng with the following command:
```
sudo apt-get install aircrack-ng
```
Secondly, a few Python Modules are required, you can install them with the following command:
```
sudo pip3 install netaddr, pandas, scapy
```
Note that if any Software is missing, the application will prompt you with and error message indicating how to insatll that software.
3.	Latest releases
GUI: SQLite Integration 
CLI: SQLite Integration
4.	API references
For more information on how to use the CaptureEngine, please refer to the documentation located inside the CaptureEngine.py file.

# Build and Test
###CLI:
To run the application, make the Python script executable with:
```
sudo chmod u+x ./cli.py
```
Then, execute the script with:
```
sudo ./cli.py
```
###GUI:
To run the application, make the Python script executable with:
```
sudo chmod u+x ./gui.py
```
Then, execute the script with:
```
sudo ./gui.py
```

# Contribute
Please, feel free to add modifications to the CaptureEngine. For more information, please refer to the documentation inside the code.
For more information on the Scapy module, visit https://scapy.net/.
