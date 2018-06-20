#!/usr/bin/python

##############################################################################################################################################
import cgi, cgitb
##############################################################################################################################################
import os
import sys
import subprocess
import crypt, spwd
import time
import socket
import re
import time
##############################################################################################################################################
version		= "1.2"
activity_log	= "/tmp/activity_log.txt"
config_file	= "/var/www/config.txt"
ksz9897		= "00989700"
ksz9477		= "00947700"
KSZ9897_INFO	= "EVB-KSZ9897"
KSZ9477_INFO	= "EVB-KSZ9477"
kszid		= "None"
phy_ports	= "0"
num_ports	= "0"
log		= 1
sudocmd		= "sudo"
##############################################################################################################################################
############  Function to log command activity  ################################
def	log_activity(cmd):
	log_cmd = "echo " + time.asctime(time.localtime(time.time())) +" : "+ cmd + " >> " + activity_log
	proc = subprocess.Popen(log_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
	(out, err) = proc.communicate()
	return;

############  Function to save config to file  ################################
def	save_config(cmd):
	save_cmd = sudocmd+" swcfg SystemCfg "+ "\" " + "echo " + cmd + " >> " + config_file + " \""
	proc = subprocess.Popen(save_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
	(out, err) = proc.communicate()
	return;

############  Function to execute Shell Commands ################################
## cmd: ifconfig, swcfg ...
def	exe_shell_cmd(cmd):
	if log:
		log_activity(cmd)
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
	(out, err) = proc.communicate()
	
	return out;

############  Function to lock python script execution instance  ################################
def lock():
	pidfile = "/tmp/mydaemon.pid"
	pid = str(os.getpid())

	start = time.time()

	while os.path.isfile(pidfile) and ((time.time() - start) <= 300):
		time.sleep(0.05)
	if (time.time() - start) >= 300:
		os.unlink(pidfile)
	file(pidfile, 'w').write(pid)

############  Function to unlock python script execution instance  ################################
def unlock():
	pidfile = "/tmp/mydaemon.pid"
	os.unlink(pidfile)

############ Function to get KSZ Info ####################
def get_info():
	global kszid
	global phy_ports
	global num_ports
	global log
	log = 0
	kszid = exe_shell_cmd(sudocmd+" swcfg SwitchCfg get 0x0").strip("\n")
	num_ports = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get ports")
	log = 1
	if kszid == ksz9897 :
		phy_ports = "6"
	elif kszid == ksz9477 :
		phy_ports = "5"
	else :
		phy_ports = "0"

	return;

############ Function to get KSZ Switch Interface ####################
## return: interface name on success else -1 on failure
def	get_interface():
	global sudocmd
	
	cmdout = exe_shell_cmd("/sbin/ifconfig | grep HWaddr")

	interfaces = len(cmdout.splitlines()) - 1
	count = 0
	while   count <= interfaces:
        	intf = cmdout.splitlines()[count].split()[0]
        	out = exe_shell_cmd("/usr/sbin/ethtool --driver "+intf)
		if out.splitlines()[0].find("not found") != -1 :
        		out = exe_shell_cmd("/sbin/ethtool --driver "+intf)
        	if out.splitlines()[0].split()[1] == "lan78xx" :
                	return intf
		elif out.splitlines()[0].split()[1] == "macb" :
			sudocmd = ''
                	return intf
        	count = count+1

	return -1;

############ Function to get network info of KSZ interface  ####################
## interface: eth1
## return: <Ipaddr>:<Netmask>:<Gateway>

def network_info(interface) : 
	cmdout = exe_shell_cmd("/sbin/ifconfig "+ interface + " | grep -sw \"inet\" | tr \":\" \" \" ")
	if len(cmdout) != 0:
		response = cmdout.split()[2] + ":" + cmdout.split()[6] + ":"
		cmdout = exe_shell_cmd("/sbin/route -n"+ "| head -n3 | grep " + interface)
		if len(cmdout) != 0:
			response += cmdout.split()[1]
		else:
			response += "0.0.0.0"
	else: 
		response = "0.0.0.0:0.0.0.0:0.0.0.0"

	return response;

############ Function to validate IP  ####################
def is_valid_ipv4(addr) : 
	try:
		socket.inet_aton(addr)
	except socket.error:
		return False
	return True

############ Function to validateMAC  ####################
def is_valid_mac(mac) :
	mac_regx  = '^([a-fA-F0-9]{2}[:]){5}([a-fA-F0-9]{2})$'

	if re.compile(mac_regx).match(mac):
		return True
	else:
		return False

############ Function to set PVID Configurations  ####################
## Port: <0-6>
## PVID: <PVID Value>
## IngressFilter: 1-Enable 0-Disable
## FrameAccType: AA - AcceptALl, AT - AcceptTagged, AU-AcceptUntagged
## PortPriority: <0-7>
## return: Success string

def set_pvidCfg(Port, PVID, IngressFilter, FrameAccType, PortPriority) :

	exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(Port) + " vid " + str(int(PVID) | (int(PortPriority) << 13)))
	exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(Port) + " ingress " + str(int(IngressFilter)))
	
	if FrameAccType == "AA":
		dnv = "0"
		dv  = "0"
	else:
		if FrameAccType == "AT":
			dnv = "1"
			dv  = "0"
		else:
			dnv = "0"
			dv  = "1"
	
	exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(Port) + " drop_non_vlan " + dnv)
	exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(Port) + " drop_tagged " + dv)

	return "Success";

############ Function to get PVID information  ####################
## ports: <No of Ports>
## return: return the all Ports info >  <PVID>:<Ingress>:<FrameAccType>:<Priority>

def pvid_info(ports) :
	port = 0
	response = ''
	while (port < ports) :
		vid = int(exe_shell_cmd(sudocmd+" swcfg PortCfg get " + str(port) + " vid "),16)
		dnv = int(exe_shell_cmd(sudocmd+" swcfg PortCfg get " + str(port) + " drop_non_vlan ").split()[0])
		dv = int(exe_shell_cmd(sudocmd+" swcfg PortCfg get " + str(port) + " drop_tagged ").split()[0])
		ingress = int(exe_shell_cmd(sudocmd+" swcfg PortCfg get " + str(port) + " ingress ").split()[0])

		pvid = vid & ~(0xf000)
		#prio = ((vid & ~(0x1fff)) >> 13)

		response += str(pvid) + ":"

		response += str(ingress) + ":"
		
		if dnv == 0 and dv == 0 :
			response += "AA:"
		else:
			if(dnv == 1) :
				response += "AT:"
			else :
				response += "AU:"
		#response += str(prio) + ":"
		
		port = port + 1
		
	return response;

##############################################################################################
# 0x00 Basic Control Register	- 0.11:PowerDown 0.12:AutoNeg 0.8:DuplexMode [0.6,0.13]:Speed
# 0x01 Basic Status Register	- 1.2:LinkStatus 1.11:10HD 1.12:10FD 1.13:100HD 1.14:100FD
# 0x0a 1000Base Status Register	- a.10:HD a.11:FD
# 0x05 Partner Ability Register	- 5.8:100MFD 5.7:100MHD 5.6:10MFD 5.5:10MHD
##############################################################################################

############ Function to set Port Spped Configurations  ####################
## Port: <1-6>
## PortMode: <10MHD - 1000MFD - Auto)
## return: SUCCESS

def set_portCfg(Port,PortMode,PortSpeed) :
	# 0x00h Basic Control Register
	RegVal = int(exe_shell_cmd(sudocmd+" swcfg PhyCfg get " + str(Port) + " 0x00"),16)
################ FIXME Need to Add Phase 2 #########################
#	if PortMode == "disable":
#		RegVal |= (0x0800)	#Set PowerDown Bit 0.11
#	else:
#		RegVal &= ~(0x0800)	#Clear PowerDown Bit 0.11
###################################################################
	if PortSpeed == "Auto" :
		RegVal |= (0x1000)	#Set AutoNeg Bit 0.12
	else:
		#Set/Clear Duplex Mode Bit 0.8 : 0 - Half, 1 - Full
		#Spped Select Bit 0.6,0.13
		# [0,0] 10Mbps : [0,1] 100Mbps : [1,0] 1000Mbps
		RegVal &= ~(0x1000) #Clear AutoNeg

		if PortSpeed == "10MHD" :
			RegVal &= ~(0x2140)
		elif PortSpeed == "10MFD" :
			RegVal |= (0x0100)
			RegVal &= ~(0x2040)
		elif PortSpeed == "100MHD" :
			RegVal &= ~(0x0140)
			RegVal |= (0x2000)
		elif PortSpeed == "100MFD" :
			RegVal &= ~(0x0040)
			RegVal |= (0x2100)
		elif PortSpeed == "1000MHD" :
			RegVal &= ~(0x2100)
			RegVal |= (0x0040)
		else :
			RegVal &= ~(0x2000)
			RegVal |= (0x0140)
		
	exe_shell_cmd(sudocmd+" swcfg PhyCfg set " + str(Port) + " 0x00  " + hex(RegVal))	

# delay
	delay = 10000
	while delay:
		subdelay = 10000
		while subdelay:
			subdelay = subdelay -1

		delay = delay -1	

	return "SUCCESS"

############ Function to get PHY port settings  ####################
## ports : No of ports
## return: <Speed>:<LinkStatus LinkSpeed>

def port_info(ports) :
	port = 1
	response = ''
	while (port < ports) :
		RegBC = int(exe_shell_cmd(sudocmd+" swcfg PhyCfg get " + str(port) + " 0x00"),16)
		RegBS = int(exe_shell_cmd(sudocmd+" swcfg PhyCfg get " + str(port) + " 0x01"),16)
		RegLPA = int(exe_shell_cmd(sudocmd+" swcfg PhyCfg get " + str(port) + " 0x05"),16)
		Reg1000BS = int(exe_shell_cmd(sudocmd+" swcfg PhyCfg get " + str(port) + " 0x0a"),16)
################ FIXME Need to add in Phas 2 ###############
#		if (RegBC & (0x0800)) :
#			response += "disable:"
#		else :
#			response += "enable:"
############################################################
		if (RegBC & (0x1000)) :
			response += "Auto:"
		else :
			if (RegBC & (0x0100)) :
				if (RegBC & (0x0040)) and not(RegBC & (0x2000)) :
					response += "1000MFD:"
				elif not(RegBC & (0x0040)) and (RegBC & (0x2000)) :
					response += "100MFD:"
				else :
					response += "10MFD:" 
			else:
				if (RegBC & (0x0040)) and not(RegBC & (0x2000)) :
					response += "1000MHD:"
				elif not(RegBC & (0x0040)) and (RegBC & (0x2000)) :
					response += "100MHD:"
				else :
					response += "10MHD:" 

		if (RegBS & (0x0004)) :
			response += "Link Up"
			if (RegBC & (0x1000)) :
				if (Reg1000BS & (0x0c00)):
					if(Reg1000BS &(0x0800)):
						response += " - 1G Full Duplex:"
					else:
						response += " - 1G Half Duplex:"
				else:
					if(RegLPA & (0x0100)) :
						response += " - 100M Full Duplex:"
					elif (RegLPA &(0x0080)) :
						response += " - 100M Half Duplex:"
					elif (RegLPA &(0x0040)) :
						response += " - 10M Full Duplex:"
					else:
						response += " - 10M Half Duplex:"
			else:
				response += ":"
		else:
			response += "Link Down:"

		port = port + 1

	return response;

############ Function to get current ALU configurations  ####################
## return: <No Of ALU entries>:<AluIndex>:<MAC Addr>::<PortMemberShif[M- -M]>
def static_mac_tbl_info(maxports,index,check) :
	
	cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get static_table")
	alu = 0
	alus = len(cmdout.splitlines()) - 1
	
	empty_lines = 0
	while(alu < alus):
		aluinfo = cmdout.split('\n')[alu]
		if len(aluinfo.strip()) == 0 or len(aluinfo.split()) > 9:
			empty_lines = empty_lines + 1
		alu = alu + 1
	response = str(alus - empty_lines) + "*"
	alu = 0
	while(alu < alus):
		aluinfo		= cmdout.split('\n')[alu]
		if len(aluinfo.strip()) == 0 or len(aluinfo.split()) > 9:
			alu = alu+1
			continue
		alu_index	= int(aluinfo.split()[0].split(":")[0],16)
		alu_mac		= aluinfo.split()[1]
		mports		= int(aluinfo.split()[2],16)

		if check:
			if alu_index == int(index):
				return "Matched"

		response += str(alu_index) + "*" + alu_mac + "*"
		port = 0;
		while port < maxports:
			if(mports & 1 << port):
				response += 'M-'
			else:
				response += 'N-'
			port = port+1
		alu = alu+1
		#response = response[:-1]
		response += "*"

	return response

############ Function to validate int  ####################
def is_integer(instr) :
	try:
		int(instr)
		return True
	except ValueError:
		return False

############ Function to validate hex  ####################
def is_hex(instr) :
	try:
		int(instr,16)
		return True
	except ValueError:
		return False

############ Function to get current VLAN configurations  ####################
## return: <No Of Vlans>:<String>:<VlanID>:<FID>:<PortMemberShif[T-U-N]>

def vlan_info(check,VID,FID) :
	cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get vlan_table")
	vid = 0
	vids = len(cmdout.splitlines()) - 1
	
	response = str(vids) + ":" + "Ports:"
	
	while vid < vids:
		vidinfo	= cmdout.split('\n')[vid]
		vlanid 	= int(vidinfo.split()[0].split(":")[0],16)
		fid 	= int(vidinfo.split()[1],16)
		tagtype	= int(vidinfo.split()[5],16)
		mports 	= int(vidinfo.split()[6],16)
		response += str(vlanid) + ":" + str(fid) + ":"
		if check:
			if str(vlanid) == str(VID):
				return "Matched"
		port = 0
		maxports = 7
		while port < maxports:
			if (mports & 1 << port):
				if (tagtype & 1 << port):
					response += 'U-';
				else:
					response += 'T-';
			else:
				response += 'N-';
			port = port +1
		vid = vid+1
		response = response[:-1]
		response += ":"
		
	return response;
	
############ Function to get current STP configurations  ####################
## return: <STP Version:<Bridge Prio>:<Max Age>:<Hello Time>:<Fwd Delay>:<Tx Hold>:<Bridge Info>
def stp_info(Action) :
	cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get stp_version")
	response = cmdout.split()[0]
	cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get stp_br_prio")
	response += ":" + str(int(cmdout,16))
	cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get stp_br_max_age")
	response += ":" + str(int(cmdout))
	cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get stp_br_hello_time")
	response += ":" + str(int(cmdout))
	cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get stp_br_fwd_delay")
	response += ":" + str(int(cmdout))
	cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get stp_br_tx_hold")
	response += ":" + str(int(cmdout))
	if Action == "Save":
		config = "STPCFG#"+response
		save_config(config)
	cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get stp_br_info")
	response += ":" + cmdout

	#response = "2:53248:30:2:20:5:BridgeInfo"
	return response;

############ Function to get current STP port information  ####################
## ports : No of ports
## return: <STP State>:<Priority>:<Path Cost>:<Edge>:<Auto Edge>:<Edge Path Cost>:<Mcheck>:<P2P>:...for all Ports....:<Port stp Info>

def stp_port_info(ports) :
	port = 0
	response = ''
	while (port < ports) :
		response += str(int(exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) +" stp_on").split()[0])) + ":"
		response += str(int(exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) +" stp_prio"),16)) + ":"
		response += str(int(exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) +" stp_path_cost"))) + ":"
		response += str(int(exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) +" stp_admin_edge").split()[0])) + ":"
		response += str(int(exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) +" stp_auto_edge").split()[0])) + ":"
		response += str(int(exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) +" stp_admin_path_cost"))) + ":"
		response += str(int(exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) +" stp_mcheck").split()[0])) + ":"
		response += str(int(exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) +" stp_admin_p2p").split()[0])) + ":"
		port = port + 1

	return response;

############ Function to get tx queue configurations  ####################
def get_tx_queue_cfg(qos_port) :
	ref = 0
	queues = 4;
	tc_map = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(qos_port) + " tc_map ")
	response = tc_map.split('=')[1].split('\t')[0]
	response = response.replace(" ", ":")
	while ref < queues :
		exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(qos_port) + " q_index " + str(ref))
		sched = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(qos_port) + " q_scheduling ")
		response += sched.split()[0] + ":"
		ref = ref + 1

	return response;

############ Function to get Egress Rate Limit configurations  ####################
def get_ingress_rate_cfg(rate_limit_port,save) :
	count = 0
	priority = 8
	inprio = ''
	while count < priority:
		if save:
			inprio += exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " rx_p"+str(count)+"_rate").splitlines()[0].split()[0] + ":"
		else:
			inprio += exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " rx_p"+str(count)+"_rate").splitlines()[0] + ":"
		count = count + 1
	response = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " rx_prio_rate ").split()[0] + ":"
	response += exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " limit_port_based ").split()[0] + ":"
	response += exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " limit ").split()[0] + ":"
	if save:
		response += exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " rx_p0_rate").splitlines()[0].split()[0] + ":"
	else:
		response += exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " rx_p0_rate").splitlines()[0] + ":"
	response += inprio

	return response

############ Function to get Egress Rate Limit configurations  ####################
def get_egress_rate_cfg(rate_limit_port,save) :
	count = 0
	queues = 4
	erate = ''
	while count < queues:
		if save:
			erate += exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " tx_q"+str(count)+"_rate").splitlines()[0].split()[0] + ":"
		else:
			erate += exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " tx_q"+str(count)+"_rate").splitlines()[0] + ":"
		count = count + 1
	response = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(rate_limit_port) + " tx_prio_rate ").split()[0] + ":" + erate
	return response;

############ Function to get parsed strings of acl_table  ####################
def get_acl_info(InString):
	rule_config 	= "0"
	rule_action 	= "0"
	rule_map	= "0"
	index1 = InString.find("rules:")
	index2 = InString.find("rulesets:")
	index3 = InString.find("actions:")

	if index1 != -1:
		if index2 != -1: 
			rule_config 	= InString[index1:index2]
		elif index3 != -1 :
			rule_config 	= InString[index1:index3]
		else:
			rule_config 	= InString[index1:-1]
	if index2 != -1:
		if index3 != -1 :
			rule_map 	= InString[index2:index3]
		else:
			rule_map 	= InString[index3:-1]
	if index3 != -1:
		rule_action = InString[index3:-1]
	#response = rule_config + "#" + rule_action + "#" + rule_map
	return rule_config, rule_action, rule_map
	
############ Function to parse rules table  ####################
def parse_rc(InString, Port,Inindex,check,save):
	length = len(InString.splitlines()) -1
	index = 1
	response = " "
	tab = "\t"

	LineSepL2 = "---------------------------------- L2 ACL ---------------------------------------\n"
	LineSepL3 = "\n--------------------------------- L3 ACL ----------------------------------------\n"
	LineSepL4 = "\n-------------------------------------------------------- L4 ACL ---------------------------------------------------------------\n"
	LineSep = "\n-------------------------------------------------------------------------------------------------------------------------------\n"
	L2 = LineSepL2 + "Index\tMac Address\t\tEtherType\tCriteria\tSource\tAction\n"
	L3 = LineSepL3 + "Index\tIp Address\t\tNetmask\t\t\tCriteria\tSource\tAction\n"
	L4 = LineSepL4 + "Index\tPortMode\tMinPort\tMaxPort\tProtocol\tTCP Seq\t\tFlag\tValue\tMask\tCriteria\tSource\tAction\n"

	state = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(Port) +" acl")
	
	if save:
		aclstate = state.split()[0]
		save_cfg = ''

	if state.split()[0] == "1":
		state = "Enabled"
	else:
		state = "Disabled"

	LineHead = "\n------------------------------ ACL "+state+" --------------------------------------\n"

	while index < length :
		#rc_type = (InString.splitlines()[1]).split()[-1]
		rc_type = list((InString.splitlines()[index]).split()[-1])[1]
		acl_index = ((InString.splitlines()[index]).split()[0]).split(':')[0]
		acl_index = str(int(acl_index,16))
		if Inindex == acl_index:
			return "Matched"

		if save:
			save_cfg += aclstate + "*" + rc_type + "*" + acl_index + "*"

		if rc_type == "1":
			mac 		= ((InString.splitlines()[index]).split()[1]).split('-')[0]
			ethertype 	= ((InString.splitlines()[index]).split()[1]).split('-')[1]
			matchtype 	= list(((InString.splitlines()[index]).split()[3]))[2]
			Source 		= list(((InString.splitlines()[index]).split()[4]))[2]
			Action 		= list(((InString.splitlines()[index]).split()[5]))[2]
		
			if save:
				save_cfg += mac + "*" + ethertype + "*" + matchtype + "*" + Source + "*" + Action + "*"

			if Action == "1":
				Action = "Deny"
			else: 
				Action = "Permit"

			if Source == "1":
				Source = "Y"
			else:
				Source = "N"

			if matchtype == "1":
				matchtype = "Ethtype"
				Source = "NA"
			elif matchtype == "2":
				matchtype = "MacAddr"
			elif matchtype == "3":
				matchtype = "Both"

			L2 += acl_index+tab+mac+tab+ethertype+tab+tab+matchtype+tab+tab+Source+tab+Action + "\n"
		if rc_type == "2":
			ipaddr 		= ((InString.splitlines()[index]).split()[1]).split(':')[0]
			netmask 	= ((InString.splitlines()[index]).split()[1]).split(':')[1]
			matchtype 	= list(((InString.splitlines()[index]).split()[2]))[2]
			Source 		= list(((InString.splitlines()[index]).split()[3]))[2]
			Action 		= list(((InString.splitlines()[index]).split()[4]))[2]

			if save:
				save_cfg += ipaddr + "*" + netmask + "*" + matchtype + "*" + Source + "*" + Action + "*"

			if Action == "1":
				Action = "Deny"
			else: 
				Action = "Permit"

			if Source == "1":
				Source = "Y"
			else:
				Source = "N"

			if matchtype == "1":
				matchtype = "IPAddr"
			elif matchtype == "2":
				matchtype = "SrcDst"
				Source = "NA"
			align1 = " "
			align2 = " "
			if(len(ipaddr) == 15):
				align1 = ""
			if(len(netmask) == 15):
				align2 = ""
			L3 += acl_index+tab+ipaddr+align1+tab+tab+netmask+align2+tab+tab+matchtype+tab+tab+Source+tab+Action + "\n"
		if rc_type == "3":
			
			listlen = len(InString.splitlines()[index].split())
			refindex = 4

			if listlen == 9:
				portmode = ((InString.splitlines()[index]).split()[1]).split('=')[0] 
				minport = (((InString.splitlines()[index]).split()[1]).split('=')[1]).split('-')[0] 
				maxport = (((InString.splitlines()[index]).split()[1]).split('=')[1]).split('-')[1] 
				refindex = 2
			elif listlen == 10:
				refindex = 3
				if len(((InString.splitlines()[index]).split()[1])) > 2:
					portmode = ((InString.splitlines()[index]).split()[1]).split('=')[0]
					minport	= (((InString.splitlines()[index]).split()[1]).split('=')[1]).split('-')[0]
					maxport	= ((InString.splitlines()[index]).split()[2])
				else:
					portmode	= list(((InString.splitlines()[index]).split()[1]))[0]
					minport = ((InString.splitlines()[index]).split()[2]).split('-')[0]
					maxport = ((InString.splitlines()[index]).split()[2]).split('-')[1]
			else:
				portmode	= list(((InString.splitlines()[index]).split()[1]))[0]
				minport		= ((InString.splitlines()[index]).split()[2]).split('-')[0]
				maxport		= ((InString.splitlines()[index]).split()[3])

			protocol	= ((InString.splitlines()[index]).split()[refindex])
			tcpseq		= ((InString.splitlines()[index]).split()[refindex+1]).split(':')[1]
			tcpflag		= list(((InString.splitlines()[index]).split()[refindex+2]))[2]
			flagvalue	= (((InString.splitlines()[index]).split()[refindex+2]).split('=')[1]).split(':')[0]
			flagmask	= (((InString.splitlines()[index]).split()[refindex+2]).split('=')[1]).split(':')[1]
			matchtype 	= list(((InString.splitlines()[index]).split()[refindex+3]))[2]
			Source 		= list(((InString.splitlines()[index]).split()[refindex+4]))[2]
			Action 		= list(((InString.splitlines()[index]).split()[refindex+5]))[2]

			if save:
				save_cfg += portmode + "*" + minport + "*" + maxport + "*" + tcpseq + "*" + tcpflag + "*" 
				save_cfg += flagvalue + "*" + flagmask + "*" + protocol + "*" + matchtype + "*" + Source + "*" + Action + "*"

			if Action == "1":
				Action = "Deny"
			else: 
				Action = "Permit"

			if Source == "1":
				Source = "Y"
			else:
				Source = "N"

			if portmode == "0":
				portmode = "Disable"
			elif portmode == "1":
				portmode = "Either"
			elif portmode == "2":
				portmode = "In Rng"
			elif portmode == "3":
				portmode = "Out Rng"

			if tcpflag == "1":
				tcpflag = "Y"
			else:
				tcpflag = "N"

			if matchtype == "0":
				matchtype = "Proto"
				Source = "NA"
			elif matchtype == "1":
				matchtype = "TCPPort"
				protocol = "NA"
			elif matchtype == "2":
				matchtype = "UDPPort"
				protocol = "NA"
			elif matchtype == "3":
				matchtype = "TCP Seq"
				protocol = "NA"
				Source = "NA"

			L4 += acl_index+tab+portmode+tab+tab+minport+tab+maxport+tab+protocol+tab+tab+tcpseq+tab+tcpflag+tab+flagvalue+tab+flagmask
			L4 += tab+matchtype+tab+tab+Source+tab+Action + "\n"
		if save:
			save_cfg += '='
		index = index + 1
	L4 += LineSep
	response = LineHead + L2 + L3 + L4
	if save:
		return save_cfg
	return response

############ Function to parse ruleset table  ####################
def parse_ra(InString):
	length = len(InString.splitlines()) -1
	index = 1
	response = " "
	tab = "\t"
	LineSep = "------------------------------------------------------------------------\n"
	response = LineSep + "Index\tPrio Mode\tPrio\tPri Rep\tVlan Pri\tMap\tPort Map\n"
	while index < length :
		acl_index	= ((InString.splitlines()[index]).split()[0]).split(':')[0]
		priomode	= ((InString.splitlines()[index]).split()[1]).split(':')[1][0]
		prio		= ((InString.splitlines()[index]).split()[1]).split(':')[1][2]
		vlan		= ((InString.splitlines()[index]).split()[2]).split(':')[1][0]
		vlanprio	= ((InString.splitlines()[index]).split()[2]).split(':')[1][2]
		mapping		= ((InString.splitlines()[index]).split()[3]).split('=')[0]
		portmap		= ((InString.splitlines()[index]).split()[3]).split('=')[1]

		if priomode == "0":
			priomode = "Disable"
		elif priomode == "1":
			priomode = "Higher"
		elif priomode == "2":
			priomode = "Lower"
		elif priomode == "3":
			priomode = "Replace"

		if vlan == "1":
			vlan = "Y"
		else:
			vlan = "N"

		if mapping == "0":
			mapping = "Disable"
		elif mapping == "1":
			mapping = "AND"
		elif mapping == "2":
			mapping = "OR"
		elif mapping == "3":
			mapping = "Replace"

		response += acl_index+tab+priomode+tab+tab+prio+tab+vlan+tab+vlanprio+tab+tab+mapping+tab+portmap +"\n"
		index = index + 1

	return response

############ Function to parse rule action table  ####################
def parse_rm(InString,Port):
	length = len(InString.splitlines()) -1
	index = 1
	response = " "
	tab = "\t"
	
	state = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(Port) +" acl")
	
	if state.split()[0] == "1":
		state = "Enabled"
	else:
		state = "Disabled"

	LineSep = "------------------ACL " + state + "-----------------------\n"
	response = LineSep + "Index\tAction Index\tRule Map\n"
	
	while index < length:
		acl_index	= ((InString.splitlines()[index]).split()[0]).split(':')[0]
		action		= ((InString.splitlines()[index]).split()[1]).split(':')[0]
		ruleset		= ((InString.splitlines()[index]).split()[1]).split(':')[1]

		response += acl_index+tab+action+tab+tab+ruleset + "\n"
		index = index+1
	return response

## Function to handle HTML form requests
def	exe_py_cgi():
	#### ******************** ####
	print "Content-type: text/html"
	print ""
	#### ******************** ####
	get_info()
	if phy_ports == "0":
		return "No Device Found!!"

	if CfgType == "DevInfo" :
		response = kszid
		if kszid == ksz9897 :
			response += ":" + "6#:" + num_ports + ":" + KSZ9897_INFO
		elif kszid == ksz9477 :
			response += ":" + "5#:" + num_ports + ":" + KSZ9477_INFO
		else :
			response += "Invalid Device !"
		#print "DevID:DevCap:DevPort:DisplayString:"
	elif CfgType == "SysAuth" :
		user	= form.getvalue('UserName')
		passwd	= form.getvalue('UserPasswd')
		response = exe_shell_cmd(sudocmd+" python user_auth.py "+ user + " " +passwd)
		response = response.strip("\n")
		if response == "Success":
			exe_shell_cmd("rm " + activity_log)
		# FIXME
		response += ":NewlineHack"

	elif CfgType == "HostInfo" :
		response = "Kernel Verion:\n"
		response += exe_shell_cmd("uname -r")
		if kszid == ksz9897 :
			response += "\nOS Release:\n"
			response += exe_shell_cmd("lsb_release -a")

	elif CfgType == "DrvInfo" :
		response = "lan78xx Driver Info:\n"
		if kszid == ksz9897 :
			response += exe_shell_cmd("/sbin/ethtool --driver "+ interface)
		else:
			response += exe_shell_cmd("/usr/sbin/ethtool --driver "+ interface)
		response += "\nKSZ Driver Version:\n"
		response += exe_shell_cmd("swcfg GlobalCfg get version")
		response += "GUI Version:\n"
		response += version

	elif CfgType == "TgtInfo" :
		response = "Target Chip Id:\n"
		response += exe_shell_cmd(sudocmd+" swcfg SwitchCfg get 0x00")
		response += "\nNo Of Ports:\n"
		response += exe_shell_cmd("swcfg GlobalCfg get ports")

	elif CfgType == "SWDebug" :
		access  = form.getvalue('access')
		swreg   = form.getvalue('swReg')
		regval  = form.getvalue('RegVal')
		if swreg == None or not(is_hex(swreg)):
			response = "Failed#Please Provide a Valid Register in Hex Format!" 
			return response
		if access == "set":
			if regval == None or not(is_hex(regval)):
				response = "Failed#Please Provide a Valid Value in Hex Format!" 
				return response
		else:
			regval = "NULL"

		response = exe_shell_cmd(sudocmd+" swcfg SwitchCfg "+ access + " " + swreg + " " + regval)
		if response.splitlines()[0].split()[0] == "Traceback":
			response = ' '

	elif CfgType == "PHYDebug" :
		access  = form.getvalue('access')
		phyid   =  form.getvalue('PhyId')
		phyreg     =  form.getvalue('PhyReg')
		regval  = form.getvalue('RegVal')

		if phyreg == None or not(is_hex(phyreg)):
			response = "Failed#Please Provide a Valid PHY Register in Hex Format!" 
			return response
		if phyid == None or not(is_hex(phyid)):
			response = "Failed#Please Provide a Valid PHY ID!" 
			return response
		if access == "set":
			if regval == None or not(is_hex(regval)):
				response = "Failed#Please Provide a Valid Value in Hex Format!" 
				return response
		else:
			regval = "NULL"

		response = exe_shell_cmd(sudocmd+" swcfg PhyCfg "+ access + " " + phyid + " " + phyreg + " " + regval)

	elif CfgType == "SystemDebug" :
		cmd = form.getvalue('ShellCmd')
		response = exe_shell_cmd(cmd)

	elif CfgType == "ActivityLog" :
		global log
		log = 0
		LogClear = form.getvalue('FormCmd')
		if LogClear == "Clear" :
			exe_shell_cmd("rm " + activity_log)
		response = exe_shell_cmd("cat " + activity_log)
		if response.splitlines()[0].split(":")[2] == " No such file or directory":
			response = " "
		log = 1

	elif CfgType == "IPSettings" :
		SetType = form.getvalue('IpSetType')
		IpAddr = form.getvalue('IpAddr')
		SNMask = form.getvalue('SNMask')
		DGAddr = form.getvalue('DGAddr')
		Action = form.getvalue('IPSettingsCfg')

		if Action == "Set":
			if SetType == "manual" :
				if not(is_valid_ipv4(IpAddr)):
					return "Failed#Invalid Ip Address!"

				if not(is_valid_ipv4(SNMask)):
					return "Failed#Invalid Subnet Mask!"

				if not(is_valid_ipv4(DGAddr)):
					return "Failed#Invalid Gateway Address!"

				exe_shell_cmd(sudocmd+" swcfg SystemCfg "+ "\"ifconfig "+ interface + " " + IpAddr + " " + "netmask "+ SNMask + " up\"")
				exe_shell_cmd(sudocmd+" swcfg SystemCfg \"route add default gw " + DGAddr + "\"" )

			if SetType == "dhcp" :
				exe_shell_cmd(sudocmd+" swcfg SystemCfg \"ifconfig " + interface + " 0 up\"")
				exe_shell_cmd(sudocmd+" swcfg SystemCfg \"killall -9 dhclient \"")
				exe_shell_cmd(sudocmd+" swcfg SystemCfg \"dhclient " + interface + "\"")

		response = network_info(interface)
		if Action == "Save":
			config = "IPSETTINGS#"+str(SetType)+":"+response
			save_config(config)
			
	elif CfgType == "GVLANCfg" :
		GVlanCfg = form.getvalue('VlanState')
		Action = form.getvalue('VlanCfg')

		if Action == "Set":
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set vlan "+ str(GVlanCfg))
		
		cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get vlan")
		response = cmdout.splitlines()[0][0]
		
		if Action == "Save":
			config = "GVLAN#"+response
			save_config(config)

		if response == "1":
			response = "1:1"
		else:
			response = "0:0"

	elif CfgType == "GMTUInfo" :
		mtu_size = form.getvalue('MTUSize')
		Action = form.getvalue('MTUCfg')

		if Action == "Set" :
			if not(is_integer(mtu_size) and (int(mtu_size) >= 2000 and int(mtu_size) <=9000)):
				response = "Failed#Mut Size Must be [2000 - 9000]!"
				return response
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set mtu "+ mtu_size)

		response = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get mtu")
		response = response.splitlines()[0]

		if Action == "Save":
			config = "GMTU#" + response
			save_config(config)

	elif CfgType == "GJumboSupport" :
		jumbo_support = form.getvalue('JumboFrame')
		Action = form.getvalue('JumboCfg')

		if Action == "Set":
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set jumbo_packet "+ jumbo_support)

		cmdout = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get jumbo_packet")
		response = cmdout.splitlines()[0][0]

		if Action == "Save":
			config = "GJUMBO#"+response
			save_config(config)

		if response == "1":
			response = "1:1"
		else:
			response = "0:0"

	elif CfgType == "PortCfg" :
		Port = form.getvalue('Port')
		Action = form.getvalue('PortCfg')

		if Action == "Set" and Port != None:
			#mode = "Mode" + Port
			speed = "LinkSpeed" + Port
			# FIXME
			#PortMode	= form.getvalue(mode)
			PortSpeed	= form.getvalue(speed)
			#response = set_portCfg(int(Port),PortMode,PortSpeed)
			response = set_portCfg(int(Port),' ',PortSpeed)

		response = port_info(int(phy_ports)+1)

		if Action == "Save":
			config = "PORTCFG#"+response
			save_config(config)

		#response = "disable:10MFD:P1:disable:100MFD:P2:disable:1000MFD:P3:enable:10MHD:P4:enable:100MHD:P5:disable:1000MHD:HIT"

	elif CfgType == "VlanInfo" :
		response = vlan_info(0,0,0)
		Action = form.getvalue('VlanAction')
		if Action == "Save":
			config = "VLANCFG#"+response
			save_config(config)

	elif CfgType == "VlanCfg" :
		lock()
		VID		= form.getvalue("Vid")
		FID 		= form.getvalue('Fid')
		UntagMembers 	= form.getvalue("UntagMembers")
		VlanMembers 	= form.getvalue("VlanMembers")
		VlanAction 	= form.getvalue("VlanAction")
		VlanLoad 	= form.getvalue("VlanLoad")

		if not(is_integer(VID) and (int(VID) >= 0 and int(VID) < 4096)) or not(is_integer(FID) and (int(FID) >= 0 and int(FID) < 128)):
			response = "Failed#VID Must be [0-4095] and FID Must be [0-127]"
			unlock()
			return response
		response = vlan_info(1,VID,FID)

		exe_shell_cmd(sudocmd+" swcfg GlobalCfg set vlan_index "+ str(VID))
		exe_shell_cmd(sudocmd+" swcfg GlobalCfg set vlan_fid "+ str(FID))
		exe_shell_cmd(sudocmd+" swcfg GlobalCfg set vlan_ports "+ str(hex(int(VlanMembers))))
		exe_shell_cmd(sudocmd+" swcfg GlobalCfg set vlan_untag "+ str(hex(int(UntagMembers))))
		if VlanAction == "Add":
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set vlan_valid 1")
		else:
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set vlan_valid 0")
	
		if response == "Matched" and VlanAction == "Add" and VlanLoad == "None":
			response = "Failed#Vlan Entry "+str(VID)+" Modification Successful!"
			unlock()
			return response

		response = "Success"
		unlock()
		
	elif CfgType == "PVIDCfg" :
		Port = form.getvalue('PVIDPort')
		Action = form.getvalue('PVIDCfg')

		if Action == "Set" :
			PVID		= form.getvalue("Pvid"+Port)
			if not(is_integer(PVID) and (int(PVID) >= 0 and int(PVID) < 4096)):
				response = "Failed#PVID Must be [0-4095]"
				return response
			IngressFilter	= form.getvalue("IngressFilter"+Port)
			FrameAccType	= form.getvalue("FrameAccType"+Port)
			#PortPriority	= form.getvalue("PortPriority"+Port)
			#set_pvidCfg(int(Port)-1,PVID,IngressFilter,FrameAccType,PortPriority)
			set_pvidCfg(int(Port)-1,PVID,IngressFilter,FrameAccType,0)

		#response = "HI:1:AA:5:11:1:AA:5:11:1:AA:6:11:1:AA:6:11:1:AA:6:11:1:AA:6:11:1:AA:6:"
		response = pvid_info(int(num_ports))
		if Action == "Save":
			config = "PVIDCFG#"+response
			save_config(config)

	elif CfgType == "DynamicMACInfo" :
		TblClear = form.getvalue('FormCmd')
		TblType = form.getvalue('TblType')
		if TblClear == "Clear" :
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set "+TblType+" 0")
		response = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get "+TblType)

	elif CfgType == "StaticMacCfg" :
		lock()
		alu_index		= form.getvalue('ALUIndex')
		alu_addr		= form.getvalue('ALUMACAddr')
		alu_port_members	= form.getvalue('ALUMembers')
		alu_action		= form.getvalue('ALUAction')	
		alu_load		= form.getvalue('ALULoad')	

		if not(is_integer(alu_index) and (int(alu_index) >= 0 and int(alu_index) < 16)) or not(is_valid_mac(alu_addr)):
			response = "Failed#ALU Index Must be [0-15] and MAC Must be aa:bb:cc:dd:ee:ff format !"
			unlock()
			return response
		response = static_mac_tbl_info(int(num_ports),alu_index,1)

		exe_shell_cmd(sudocmd+" swcfg GlobalCfg set alu_index " + str(hex(int(alu_index))))
		exe_shell_cmd(sudocmd+" swcfg GlobalCfg set alu_addr " +  alu_addr)
		exe_shell_cmd(sudocmd+" swcfg GlobalCfg set alu_ports " + str(hex(int(alu_port_members))))
		
		if alu_action == "Add":
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set alu_valid 1")
		else:
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set alu_valid 0")

		if response == "Matched" and alu_action == "Add" and alu_load == "None":
			response = "Failed#Static Mac Entry "+alu_index+" Modification Successful!"
			unlock()
			return response
		response = "Success"
		unlock()
		#response = str(hex(int(alu_index))) + ":" + alu_addr + "#" + str(hex(int(alu_port_members)))
			
	elif CfgType == "StaticMacInfo" :
		Action	= form.getvalue('ALUAction')	

		response = static_mac_tbl_info(int(num_ports),"-1",0)
		if Action == "Save":
			config = "STATICMACCFG#"+response
			save_config(config)
		#response = "1*10*AA:BB:CC:DD:EE:FF*M-M-M- -M-M-M"

	elif CfgType == "STPCfg" :
		stp_version 		= form.getvalue('STPVersion')
		stp_br_prio 		= form.getvalue('STPPrio')
		stp_br_max_age 		= form.getvalue('STPMaxAge')
		stp_br_fwd_delay	= form.getvalue('STPFwDelay')
		stp_br_tx_hold		= form.getvalue('STPTxHoldCount')
		Action			= form.getvalue('STPCfg')
		if Action == "Set" :
			if not(is_integer(stp_br_max_age) and (int(stp_br_max_age) >= 6 and int(stp_br_max_age) <= 30)) or not(is_integer(stp_br_fwd_delay) and (int(stp_br_fwd_delay) >= 4 and int(stp_br_fwd_delay) <= 30)) or not(is_integer(stp_br_tx_hold) and (int(stp_br_tx_hold) >= 1 and int(stp_br_tx_hold) <= 10)):
				response = "Failed#Invalid Input!\nBridge age must be [6-30]\nForward Delay must be [4-30]\nTransmit Hold Must be [1-10]"
				return response
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set stp_version " + str(int(stp_version)))
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set stp_br_prio " + hex(int(stp_br_prio)))
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set stp_br_max_age " + str(int(stp_br_max_age)))
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set stp_br_fwd_delay " + str(int(stp_br_fwd_delay)))
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set stp_br_tx_hold " + str(int(stp_br_tx_hold)))

		response = stp_info(Action)
		#response = "2:53248:30:2:20:5:BridgeInfo"

	elif CfgType == "STPPortCfg" :
		stp_port 	= form.getvalue('STPPort')
		stp_info_get 	= form.getvalue('FormCmd')
		stp_port_load 	= form.getvalue('STPPortLoad')
		if stp_port != None and stp_info_get == "Set":
			stp_port_state		= form.getvalue('STPPortState'+stp_port)
			stp_port_prio 		= form.getvalue('STPPortPrio'+stp_port)
			stp_path_cost 		= form.getvalue('STPPathCost'+stp_port)
			stp_port_edge 		= form.getvalue('STPPortEdge'+stp_port)
			stp_auto_edge 		= form.getvalue('STPPortAutoEdge'+stp_port)
			stp_edge_path_cost 	= form.getvalue('STPEdgePathCost'+stp_port)
			stp_port_mcheck 	= form.getvalue('STPPortMcheck'+stp_port)
			stp_port_p2p 		= form.getvalue('STPPortPTP'+stp_port)

			if (not(is_integer(stp_path_cost) and (int(stp_path_cost) >= 1 and int(stp_path_cost) <= 200000000)) or not(is_integer(stp_edge_path_cost) and (int(stp_edge_path_cost) >=0 and int(stp_edge_path_cost) <= 200000000))) and stp_port_load == "None":
				response = "Failed#Invalid Input!\nPath Cost Must be [1-200000000]\nEdge Path Cost Must be [0-200000000]"
				return response

			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(int(stp_port) - 1) + " stp_on " + str(int(stp_port_state)))
			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(int(stp_port) - 1) + " stp_prio " + str(hex(int(stp_port_prio))))
			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(int(stp_port) - 1) + " stp_admin_edge " + str(int(stp_port_edge)))
			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(int(stp_port) - 1) + " stp_auto_edge " + str(int(stp_auto_edge)))
			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(int(stp_port) - 1) + " stp_path_cost " + str(int(stp_path_cost)))
			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(int(stp_port) - 1) + " stp_admin_path_cost " + str(int(stp_edge_path_cost)))
			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(int(stp_port) - 1) + " stp_mcheck " + str(int(stp_port_mcheck)))
			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(int(stp_port) - 1) + " stp_admin_p2p " + str(int(stp_port_p2p)))

		response = stp_port_info(int(phy_ports))
		
		if stp_info_get == "Save":
			config = "STPPORTCFG#"+response
			save_config(config)

		if stp_port != None:
			response += exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(int(stp_port)-1) +" stp_info")
		else :
			response += "Please select a Port"
		#response ="1:16:11:1:0:12:0:0:1:16:11:1:0:12:0:0:1:16:11:1:0:12:0:0:1:16:11:1:0:12:0:0:1:16:11:1:0:12:0:0:1:16:11:1:0:12:0:0:Port Not Selected"
		
	elif CfgType == "ACLRuleCfg" :
		lock()
		acl_port = form.getvalue('ACLRulePort')
		Action = form.getvalue('ACLRuleCfg')
		Load = form.getvalue('ACLRuleCfgLoad')
		acl_mode = form.getvalue('ACLRuleType')

		response = 'NotMatched'
		if acl_port != None:
			if Action == "Add" or Action =="Delete" :
				acl 		= form.getvalue('ACLEnable')
				acl_index	= form.getvalue('ACLIndex')
				acl_enable	= form.getvalue('RuleEnable')
				acl_src		= form.getvalue('RuleSrc')
				acl_equal	= form.getvalue('RuleEqual')

				cmdout = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(acl_port) +" acl_table")
				rc, ra, rm = get_acl_info(cmdout)
				response = rc
				if response != "0":
					response = parse_rc(str(rc), acl_port,acl_index,True,False)

				if not(is_integer(acl_index) and (int(acl_index) >= 0 and int(acl_index) < 16)):
					response = "Failed#ACL Index must be [0-15]"
					unlock()
					return response

				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_index " + str(hex(int(acl_index))))
				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_act_index " + str(hex(int(acl_index))))
				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_rule_index " + str(hex(int(acl_index))))

				if acl_mode == "1": #L2
					acl_addr	= form.getvalue('RuleMacAddr')
					acl_type	= form.getvalue('RuleEtherType')
				
					if not(is_valid_mac(acl_addr)):
						response = "Failed#Mac Address should be aa:bb:cc:dd:ee:ff Format!"
						unlock()
						return response
					if not(is_hex(acl_type) and (int(acl_type,16) >= 0x0000 and int(acl_type,16) <=0xFFFF)):
						response = "Failed#EtherType should be 0x8086 Format and should be [0x000 - 0xffff]"
						unlock()
						return response

					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_addr " + str(acl_addr))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_type " + str(acl_type))
				if acl_mode == "2": #L3
					acl_ip_addr	= form.getvalue('RuleIPAddr')
					acl_ip_mask	= form.getvalue('RuleNetMask')

					if not(is_valid_ipv4(acl_ip_addr)):
						response = "Failed#Invalid IP Address"
						unlock()
						return response
					if not(is_valid_ipv4(acl_ip_mask)):
						response = "Failed#Invalid NetMask"
						unlock()
						return response

					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_ip_addr " + str(acl_ip_addr))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_ip_mask " + str(acl_ip_mask))
				if acl_mode == "3": #L4
					acl_port_mode		= form.getvalue('RulePortMode')
					acl_min_port		= form.getvalue('RuleMinPort')
					acl_max_port		= form.getvalue('RuleMaxPort')
					acl_seqnum		= form.getvalue('RuleTCPSeqNum')
					acl_tcp_flag_enable	= form.getvalue('RuleFlagEnable')
					acl_tcp_flag		= form.getvalue('RuleFlagValue')
					acl_tcp_flag_mask	= form.getvalue('RuleFlagMask')
					acl_protocol		= form.getvalue('RuleIPProtocol')

					if acl_enable == "1" or acl_enable =="2":
						if not(is_hex(acl_min_port) and (int(acl_min_port,16) > 0x0000 and int(acl_min_port,16) <= 0xFFFF)) or not(is_hex(acl_max_port) and (int(acl_max_port,16) > 0x0000 and int(acl_max_port,16) <= 0xFFFF)):
							response = "Failed#Port Number must be [0x0001 - 0xFFFF]"
							unlock()
							return response
					if acl_enable == "0":
						if not(is_hex(acl_protocol) and (int(acl_protocol,16) >= 0x00 and int(acl_protocol,16) <= 0xFF)):
							response = "Failed#Protocol Must be [0x00 - 0xFF]"
							unlock()
							return response
					if acl_enable == "3":
						if not(is_hex(acl_seqnum) and (int(acl_seqnum,16) >= 0x00000000 and int(acl_seqnum,16) <= 0xFFFFFFFF)):
							response = "Failed#TCP Seq Number must be [0x00000000 - 0xFFFFFFFF]"
							unlock()
							return response
						if acl_tcp_flag_enable == "1":
							if not(is_hex(acl_tcp_flag) and (int(acl_tcp_flag,16) >= 0x00 and int(acl_tcp_flag,16) <= 0xFF)) or not(is_hex(acl_tcp_flag_mask) and (int(acl_tcp_flag_mask,16) >= 0x00 and int(acl_tcp_flag_mask,16) <= 0xFF)):
								response = "Failed#Invalid Input!\nTCP Flag Must be [0x00 - 0xFF]\nTCP Flag Mask Must be [0x00 - 0xFF]"
								unlock()
								return response
				
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_port_mode " + str(acl_port_mode))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_min_port " + str(int(acl_min_port,16)))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_max_port " + str(int(acl_max_port,16)))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_seqnum " + str(acl_seqnum))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_tcp_flag_enable " + str(acl_tcp_flag_enable))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_tcp_flag " + str(acl_tcp_flag))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_tcp_flag_mask " + str(acl_tcp_flag_mask))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) +" acl_protocol "+ str(acl_protocol))

				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl " + str(acl))
				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_src " + str(acl_src))
				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_enable " + str(acl_enable))
				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_equal " + str(acl_equal))
				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_map_mode " + str(2))
				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_first_rule " + str(hex(int(acl_index))))
				if Action == "Add":
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_mode " + str(acl_mode))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_act 1 ")
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_ruleset " + str(hex(1 << int(acl_index))))
				else :
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_mode 0")
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_act 0")
					exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_ruleset 0")
		else:
			response = "Please select a Port and Refresh !"
			unlock()
			return response
		if response == "Matched" and Load == "None":
			response = "Failed#ACL Index "+acl_index+" Modification Successful!"
			unlock()
			return response

		cmdout = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(acl_port) +" acl_table")

		rc, ra, rm = get_acl_info(cmdout)

		response = rc

		if Action == "Save":
			port = 0
			config = "ACLCFG#"
			while port < int(phy_ports):
				cmdout = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) +" acl_table")
				rcs, ras, rms = get_acl_info(cmdout)
				if rcs == "0":
					config += "NA*"
				else:
					config += parse_rc(str(rcs), port,0,False,True)
				config += "-"
				port = port + 1
			save_config(config)
			#return response
		if response == "0":
			response = "No Information Avaliable"
			unlock()
			return response

		response = parse_rc(str(rc), acl_port,0,False,False)
		unlock()
		#response = (rc.splitlines()[1]).split()[-1]

	#elif CfgType == "ACLRuleActionConfig" :
	#	acl_port 		= form.getvalue('ACLActionPort')
	#	acl_port_members	= form.getvalue('ACLPortMembers')
	#	Action	 		= form.getvalue('ACLAction')
	#	
	#	if acl_port != None :
	#		if Action == "Add" or Action == "Delete":
	#			acl_act_index		= form.getvalue('ACLIndex')
	#			acl_map_mode		= form.getvalue('ActionMapMode')
	#			acl_prio_mode		= form.getvalue('ActionPriorityMode')
	#			acl_prio		= form.getvalue('ActionPriority')
	#			acl_vlan_prio_replace	= form.getvalue('ActionVLANPriorityReplace')
	#			acl_vlan_prio		= form.getvalue('ActionVLANPriority')
#
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_act_index " + str(hex(int(acl_act_index))))
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_map_mode " + str(acl_map_mode))
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_prio_mode " + str(acl_prio_mode))
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_prio " + str(acl_prio))
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_vlan_prio_replace " + str(acl_vlan_prio_replace))
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_vlan_prio " + str(acl_vlan_prio))
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_ports " + str(hex(int(acl_port_members))))
	#			if Action == "Add":
	#				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_act 1 ")
	#			else :
	#				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_act 0")
	#	else:
	#		response = "Port Not Selected#Port Not Selected"
	#		return response
#
	#	cmdout = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(acl_port) +" acl_table")
	#	rc, ra, rm = get_acl_info(cmdout)
	#	if ra == "0":
	#		response = "No Information Avaliable"
	#	else:
	#		#response = ra.replace(":","#")
	#		#response = ra.replace("actions:","actions-")
	#		#response = ra
	#		response = parse_ra(str(ra))
	#	if rc == "0":
	#		response += "#No Information Avaliable"
	#	else:
	#		#response += ":" + rc.replace(":","#")
	#		#response += "#" + rc
	#		response += "#" + parse_rc(str(rc))
	#	#response = "Port Selected: PortSelected#"
	#
	#elif CfgType == "ACLRuleMapCfg" :
	#	acl_port	= form.getvalue('ACLRuleMapPort')
	#	Action 		= form.getvalue('ACLMap')
#
	#	if acl_port != None:
	#		if Action == "Add" or Action == "Delete":
	#			acl 		= form.getvalue('ACLEnable')
	#			acl_rule_index	= form.getvalue('ACLRuleIndex')
	#			acl_first_rule	= form.getvalue('ACLActionIndex')
	#			acl_ruleset	= form.getvalue('ACLRuleMap')
#
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl " + str(acl))
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_rule_index " + str(acl_rule_index))
	#			exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_first_rule " + str(acl_first_rule))
	#			if Action == "Add":
	#				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_ruleset " + str(acl_ruleset))
	#			else :
	#				exe_shell_cmd(sudocmd+" swcfg PortCfg set " + str(acl_port) + " acl_ruleset 0")
	#	else:
	#		response = "Port Not Selected#Port Not Selected#Port Nost Selected"
	#		return response
#
	#	cmdout = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(acl_port) +" acl_table")
	#	rc, ra, rm = get_acl_info(cmdout)
	#	if rm == "0":
	#		response = "No Information Avaliable"
	#	else:
	#		#response = rm.replace(":","#")
	#		response =  parse_rm(rm,acl_port)
	#	if ra == "0":
	#		response += "#No Information Avaliable"
	#	else:
	#		#response += ":" + ra.replace(":","#")
	#		response += "#" + parse_ra(str(ra))
	#	if rc == "0":
	#		response += "#No Information Avaliable"
	#	else:
	#		#response += ":" + rc.replace(":","#")
	#		#response += "#" + rc
	#		response += "#" + parse_rc(str(rc))
	#	#response = "Port Selected:Port Selected:Port Selected"
#
	elif CfgType == "QueueCfg":
		lock()
		qos_port = form.getvalue('QueueCfgPort')

		if qos_port != None:
			ref = 0;
			priority = 8;
			queues = 4;
			response = ''
	
			Action = form.getvalue('QueueCfg')

			if Action == "Set" :
				while ref < priority :
					qid = form.getvalue('Port'+str(ref)+'QueueId')
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(qos_port) + " tc_map " + str(ref) + "=" + str(qid))
					response += str(qid) + ":"
					ref = ref + 1
				ref = 0
				while ref < queues :
					sched = form.getvalue('Queue'+str(ref)+'sched')
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(qos_port) + " q_index " + str(ref))
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(qos_port) + " q_scheduling " + str(sched))
					response += str(sched) + ":"
					ref = ref + 1

			if Action == "Save":
				port = 0
				config = "QOSQUEUECFG#"
				while port < int(phy_ports):
					config += get_tx_queue_cfg(port)
					port = port + 1
				save_config(config)
				response = get_tx_queue_cfg(port-1)
				unlock()
				return response

			response = get_tx_queue_cfg(qos_port)
		else:
			response = "Failed#Please select Port to get/set configurations"
		unlock()

	elif CfgType == "QueueMapCfg":
		Action = form.getvalue('QueueMapCfg')

		response = ''
		if Action == "Set" :
			port = 0
			p8021 = form.getvalue('p8021')
			diffserv = form.getvalue('diffserv')
			while port < int(phy_ports):
		 		if (int(p8021) & (1 << port)) :	
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+str(port)+" p_802_1p 1")
				else:
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+str(port)+" p_802_1p 0")
		 		if (int(diffserv) & (1 << port)) :	
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+str(port)+" diffserv 1")
				else:
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+str(port)+" diffserv 0")
				portqos = form.getvalue('portqos'+str(port+1)+'QueueId')
				exe_shell_cmd(sudocmd+" swcfg PortCfg set "+str(port)+" port_prio "+str(portqos))
				port = port + 1

			ref = 0
			priority = 8
			while ref < priority:
				queue = form.getvalue('8021p'+str(ref)+'QueueId')
				exe_shell_cmd(sudocmd+" swcfg GlobalCfg set p_802_1p_map " + str(ref)+"="+str(int(queue)))
				ref = ref + 1
			ref = 0
			priority = 64
			while ref < priority:
				queue = form.getvalue('dscp'+str(ref)+'QueueId')
				exe_shell_cmd(sudocmd+" swcfg GlobalCfg set diffserv_map " + str(ref)+"="+str(int(queue)))
				ref = ref + 1
		port = 0
		p8021 = 0
		diffserv = 0
		portqos = ''
		while port < int(phy_ports):
			cmdout = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+str(port)+" port_prio").split()[0]
			cmdout1 = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+str(port)+" p_802_1p").split()[0]
			cmdout2 = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+str(port)+" diffserv").split()[0]
			if int(cmdout1.split()[0]):
				p8021 |= (1 << port)
			if int(cmdout2.split()[0]):
				diffserv |= (1 << port)
			portqos += str(cmdout) + ":"
			port = port + 1
		response = str(p8021) + ":" + str(diffserv) + ":" + portqos 
		pcp = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get p_802_1p_map")
		dscp = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get diffserv_map")
		pcplen = len(pcp.splitlines())-1
		dscplen = len(dscp.splitlines())-1
		count = 0
		while count < pcplen:
			queue = pcp.splitlines()[count].split('=')[1].split('\t')[0]
			queue = queue.replace(" ", ":")
			response += queue
			count = count + 1
		count = 0
		while count < dscplen:
			queue = dscp.splitlines()[count].split('=')[1].split('\t')[0]
			queue = queue.replace(" ", ":")
			response += queue
			count = count + 1
		if Action == "Save":
			config = "QOSMAPCFG#"+response
			save_config(config)
		#response += str(qos_type)
		#response =  "1:1:1:1:1:1:1:1:"
		#response += "3:3:3:3:3:3:3:3:3:3:3:3:3:3:3:3:"
		#response += "3:3:3:3:3:3:3:3:3:3:3:3:3:3:3:3:"
		#response += "3:3:3:3:3:3:3:3:3:3:3:3:3:3:3:3:"
		#response += "3:3:3:3:3:3:3:3:3:3:3:3:3:3:3:3:"

	elif CfgType == "InRateLimitCfg":
		Action = form.getvalue('InRateLimitCfg')

		rate_limit_port = form.getvalue('InRateLimitPort')
		ingress		= form.getvalue('InRateLimit')
		ingress_type	= form.getvalue('InRateType')
		ingress_mode	= form.getvalue('InRateMode')

		if rate_limit_port != None:
			exe_shell_cmd(sudocmd+" swcfg PortCfg set "+str(rate_limit_port)+" limit_packet_based 1")

			count = 0
			priority = 8
			if Action == "Set" :
				exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " rx_prio_rate "+str(ingress))
				exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " limit_port_based "+str(ingress_type))
				exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " limit "+str(ingress_mode))
			warn = 0
			while count < priority:
				if Action == "Set" and not(int(ingress)):
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " rx_p"+str(count)+"_rate 0")

				if Action == "Set" and ingress_type == "0":
					rate = form.getvalue('Pri'+str(count))

					if int(ingress):
						if not(is_integer(rate)) or (int(rate) < 0):
							return "Failed# Invalid input,  Rate must be integer and > 0 !"
					
						exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " rx_p"+str(count)+"_rate "+str(rate))
					if int(rate):
						warn |= (1 << count)
				count = count + 1
			if Action == "Set" and int(ingress) and ingress_type == "0" and not(warn):
				return "Failed#At least one Rate Must be non zero!"

			if Action == "Set" and ingress_type == "1":
				if int(ingress):
					rate = form.getvalue('Rate')	
					if not(is_integer(rate)) or (int(rate) <= 0):
						return "Failed#Invalid input! Rate Must be integer and should be > 0"
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " rx_p0_rate "+str(rate))
				else:
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " rx_p0_rate 0")


			if Action == "Save":
				port = 0
				config = "INGRESSRATECFG#"
				while port < int(phy_ports):
					config += get_ingress_rate_cfg(port,1);
					port = port + 1
				save_config(config)
				response = get_ingress_rate_cfg((port-1),0);
				return response
			response = get_ingress_rate_cfg(rate_limit_port,0)
		else:
			response = "Failed#Port Not selected!"
		#response = "2Kbps:10Mbps:100Mbps:1000Mbps:64Kbps:512Kbps:32Kbps:50Mbps:"
		#response += "1Kbps:8Kbps:100Mbps:1Mbps:"

	elif CfgType == "EgRateLimitCfg":
		rate_limit_port = form.getvalue('EgRateLimitPort')
		
		if rate_limit_port != None:
			Action = form.getvalue('EgRateLimitCfg')
			egress	= form.getvalue('EgRateLimit')

			exe_shell_cmd(sudocmd+" swcfg PortCfg set "+str(rate_limit_port)+" limit_packet_based 1")

			count = 0
			queues = 4
			if Action == "Set" :
				exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " tx_prio_rate "+str(egress))

			warn = 0
			while count < queues:
				if Action == "Set" and int(egress):
					rate = form.getvalue('Queue'+str(count))
					if not(is_integer(rate)) or (int(rate) < 0):
						return "Failed# Invalid input,  Rate must be integer and > 0 !"
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " tx_q"+str(count)+"_rate "+str(rate))
					if int(rate):
						warn |= (1 << count)
				if Action == "Set" and not(int(egress)):
					exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(rate_limit_port) + " tx_q"+str(count)+"_rate 0")
				count = count + 1
		
			if Action == "Set" and int(egress) and not(warn):
				return "Failed#At least one Rate Must be non zero!"
			if Action == "Save":
				port = 0
				config = "EGRESSRATECFG#"
				while port < int(phy_ports):
					config += get_egress_rate_cfg(port,1);
					port = port + 1
				save_config(config)
				response = get_egress_rate_cfg((port-1),0);
				return response
			response = get_egress_rate_cfg(rate_limit_port,0);
		else:
			response = "Failed#Port Not selected!"

	elif CfgType == "SWStats" :
		MIBClear = form.getvalue('FormCmd')
		if MIBClear == "Clear" :
			exe_shell_cmd(sudocmd+" swcfg GlobalCfg set mib 0")
		response = exe_shell_cmd(sudocmd+" swcfg GlobalCfg get mib")

	elif CfgType == "PortStats" :
		MIBClear = form.getvalue('FormCmd')
		Port = form.getvalue('StatPort')
		if Port != None:
			if MIBClear != None and MIBClear == "Clear" :
				response = exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(Port) + " mib 0")
			response = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(Port) + " mib")
		else:
			response = "Port Not Selected!"

	elif CfgType == "MirrorCfg":
		Action = form.getvalue('MrrCfg')
		MrrLoad = form.getvalue('MrrLoadCfg')
		CapPort = form.getvalue('CapPort')
		MrrRx = form.getvalue('MrrRx')
		MrrTx = form.getvalue('MrrTx')

		if Action == "Set":
			if int(CapPort):
				exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str((int(CapPort)-1)) + " mirror_port 1")
		response = ''

		port = 0
		mrr_tx = 0
		mrr_rx = 0
		cap_port = "0"
		while port < int(num_ports) :
			if Action == "Set" and not(int(CapPort)):
				exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(port) + " mirror_port 0")
			cmdout = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) + " mirror_port ")
			if int(cmdout.split()[0]):
				cap_port = str(port+1)

		 	if Action == "Set" and (int(MrrRx) & (1 << port)) :	
				exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(port) + " mirror_rx 1")
			elif Action == "Set":
				exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(port) + " mirror_rx 0")
			cmdout = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) + " mirror_rx ")
			if int(cmdout.split()[0]):
				mrr_rx |= (1 << port)

		 	if Action == "Set" and (int(MrrTx) & (1 << port)) :	
				 exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(port) + " mirror_tx 1")
			elif Action == "Set":
				 exe_shell_cmd(sudocmd+" swcfg PortCfg set "+ str(port) + " mirror_tx 0")
			cmdout = exe_shell_cmd(sudocmd+" swcfg PortCfg get "+ str(port) + " mirror_tx ")
			if int(cmdout.split()[0]):
				mrr_tx |= (1 << port)
			port = port + 1
		response += cap_port + ":" + str(mrr_rx) + ":" + str(mrr_tx)
		
		if Action == "Save":
			config = "MIRRORING#"+response
			save_config(config)

		if Action == "Set" :
			if (int(MrrTx) & (int(MrrTx) -1)) :
				exe_shell_cmd(sudocmd+" swcfg GlobalCfg set mirror_mode 1")
			else:
				exe_shell_cmd(sudocmd+" swcfg GlobalCfg set mirror_mode 0")

		if Action == "Set" and MrrLoad == "None" and int(CapPort) and ((int(MrrRx) & (int(MrrRx) -1)) or (int(MrrTx) & (int(MrrTx) -1))):
			response += "#Info#Multiple mirror ports selected!. Congestion may happen on sniffer Port."

	elif CfgType == "SaveCfg" :
		response = exe_shell_cmd(sudocmd+" swcfg SystemCfg "+"\" rm " + config_file + " \"")
		response = "Success:Click on Config.txt to download configurations !"+ response
	else:
		print "Invalid Request!"
		exit()
	#cgi.escape(exe_shell_cmd("ifconfig"))

	return response

##############################################################################################################################################

## To check if KSZ device present ##
log = 0
interface = get_interface()
log = 1
if isinstance(interface, int):
	print "Content-type: text/html"
	print ""
	print "No Device Found!"
	exit()

sysfs	= "/sys/class/net/"+ interface
sw	= sysfs + "/sw"

## Getting Form Parameters
form = cgi.FieldStorage()
CfgType	= form.getvalue("CMD") ## CMD is PostMethod argument to differentiate the request type.

print exe_py_cgi() ## Backend request / response Processing

exit()

##############################################################################################################################################
