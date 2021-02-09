
Probe Request Analyser

  

Author: Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)

  

Inspired by wifite (https://github.com/derv82/wifite)

  
## Intro
This python app captures probe requests from a compatible wlan monitor interface. It sets up the interface on its own, captures the requests and saves them to the disk (if enabled). It can also read back .pcap files to extract relevant fields and save them in a csv format.

For help on how to use the app, run with -h or --help.

## QCA6174A INSTALLATION

When using this program with the QCA6174A, you need to install a custom firmware that supports rawmode and cryptmode. 

You can use the firmware found at https://github.com/kvalo/ath10k-firmware/raw/master/QCA6174/hw3.0/4.4.1.c3/firmware-6.bin_WLAN.RM.4.4.1.c3-00075.

Download the firmware file and rename it to firmware-2.bin. Now to install the firmware:
(Note, the card used in the buspas module is hw3.0)

* Back up the original firmware for your machine:
```bash
	cd /lib/firmware/ath10k/QCA6174
	sudo cp -r hw[hw_version] hw[hw_version]_ori
```
* Remove the old firmware files:
```bash
	 sudo rm /hw[hw_version]/firmware-*.bin
```
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
