################################################ Introduction #######################################################

KSZ/kernels/linux-3.18/		>> Kernel path contain the EVB-KSZ9897 driver
KSZ/app_uitls/mdio-tool/	>> Contains the PHY register read/write tool
KSZ/app_utils/regs_bin/		>> Contains the KSZ register read/write access tool
KSZ/app_utils/web-gui/		>> Contails the web GUI tools

#####################################################################################################################

################################## Build Instructions for EVB-KSZ9897  ##############################################

-----------------------------     Linux Distrubution # x86 Ubuntu 14.04 LTS    ----------------------------------------
* Install build dependencies you Ubuntu distrubution should be done once for distrubution
	> sudo apt-get update
	> sudo apt-get install build-essential
	> sudo apt-get install libncurses5-dev
	> sudo apt-get install vim lighttpd
---------------------------------------------------------------------------------------------------------------------

*****************           Building the Kernel source with EVB-KSZ9897 Support    **********************************
* Navigate to kernel source "KSZ/kernels/linux-3.18"

* Select LAN78xx module and KSZ9897 support form menuconfig
	> make menuconfig
	# Navigate to following and select LAN78xx modules and save config 
		#> Device Drivers
			#> Networking Device Support
				#> USB Network Adapters
					#> <M> Microchip LAN78XX Based USB Ethernet Adapters 
						#> <*> KSZ9897 Switch Support

* Build Kernel
	> make && make modules 

* Install Kernel
	> sudo make modules_install
	> sudo make install

* Reboot the system 
	> Select "Advanced options for Ubuntu" from Grub menu 
	> Select Kernel version 3.18.14

* After bootup connect EVB-KSZ9897 via USB interface to x86 system to have EVB-KSZ9897 driver access

*********************************************************************************************************************

**********************************           Building the tools           *******************************************

* MDIO-TOOL
	> Navigate to KSZ/app_utils/mdio-tool 
	> make
	> sudo cp mdio-tool /usr/sbin/
	> mdio-tool [r/w] [dev] [reg] [port] [val]      # to access phy registers
		## r/w	> to read/write register
		## dev	> Interface name "ex eth1"
		## reg	> Register address
		## port	> PHY port number [1-6]
		## val	> value to be written
	> Ex. To Read	>> mdio-tool r eth1 0x02 4
	> Ex. To Write	>> mdio-tool w eth1 0x10 0x24

* REGS_BIN
	> Navigate to KSZ/app_utils/regs_bin
	> make
	> sudo cp regs_bin /usr/sbin/
	> regs_bin	# to get access to read/write prompt, need to execute with root permissions
	> Ex. sudo regs_bin eth2	# to connect to Ethernet interface to have swith register access
	> Ex. To Read	>> r 0x01
	> Ex. To Write	>> w 0x304 0x3046

* WEB-GUI
	> Navigate to KSZ/app_utils/web-gui
	> sudo lighttpd-enable-mod cli
	> sudo /etc/init.d/lighttpd force-reload
	> sudo cp cli/swcfg /usr/sbin/
	> sudo chmod +x /usr/sbin/swcfg
	> sudo mkdir /var/www/cgi-bin
	> sudo cp backend/* /var/www/cgi-bin/
	> sudo chmod +x /var/www/cgi-bin/*
	> sudo cp frontend/* /var/www
	> sudo vim /etc/sudoers
	> Add following line next to root
		# www-data ALL= NOPASSWD: /usr/bin/python, /usr/sbin/regs_bin, /usr/sbin/mdio-tool, /usr/sbin/swcfg
	> Open browser and open "localhost" to get WEB-GUI access
	
*********************************************************************************************************************

################################################END##################################################################
