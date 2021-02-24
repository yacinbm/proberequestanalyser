
Probe Request Analyser

  

Author: Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

  

Inspired by wifite (https://github.com/derv82/wifite)

  
# Intro
This python app captures probe requests from a compatible wlan monitor interface. It sets up the interface on its own, captures the requests and saves them to the disk (if enabled). It can also read back .pcap files to extract relevant fields and save them in a csv format.

## CLI
For help on how to use the command line interface, run with -h or --help.

## GUI
To run the GUI, simply execute it with:
```bash
sudo python3 gui.py
```

You can change the RSSI threshold of the captured packets, the active interface, start and stop a capture, see a summary of the captured data and save the results in a .csv and .pcap. 

# Software Dependencies
The application requires the installation of *aircrack-ng* in order to programatically set wireless interface to monitor mode. To install, run:
```bash
sudo apt-get install aircrack-ng
``` 
The software also requires Python3 and pip. These come by default with the Jetson Nano L4T base image. 
## Python Dependencies
The application requires a few python packages to run. To install them, run:
```bash
pip3 install tkinter scapy pandas netaddr
```

# QCA6174A Installation

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
