#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  netscan.py
#  
#  Copyright 2021  <pi@markofficehost>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  use at own risk
#
#  use for edu purposes only
#  made by MarkApppprogammer
#
#

#imports
from time import sleep
import sys
import subprocess
from scapy.all import *

#vars
src_port = 10000 #CHANGE THIS
dst_port = 80
port80open = False

#the code

#some design stuff
print(" _   _      _   ____")                  
print("| \ | | ___| |_/ ___|  ___ __ _ _ __  ")
print("|  \| |/ _ \ __\___ \ / __/ _` | '_ \ ")
print("| |\  |  __/ |_ ___) | (_| (_| | | | | ")
print("|_| \_|\___|\__|____/ \___\__,_|_| |_| ")


print("")

#asks for IP 
IP = input("[*]Enter IP: ")
IP = dst_ip
sleep(0.5)
print("[*] Using nmap to scan for vunls...")
sleep(0.5)
print("[*] This may take some time...")


#runs nmap command
command = "nmap -sC -sV " + IP #EDIT NMAP COMMAND
sys.stdout.flush()
p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
(output, err) = p.communicate()
newoutput = str(output, 'UTF-8')

#prints output of nmap
print ("{}".format(newoutput))

#chek interface 
print("[*] What interface are you using?")
interface = input("[*] Interface: ")
print("[*] Checking port vulns using scapy...")
sleep(0.5)

#all functions
def webservertests():
	sleep(0.5)
	print("[*] Starting network tests")
	sleep(0.5)
	print("[*] Starting gobuster...")
	wordlistlocation = input("[*] Where is the wordlist you want to use: ")
	command = "gobuster -u " + IP + " -w " + wordlistlocation #EDIT GOBUSTER COMMAND
	sys.stdout.flush()
	p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	newoutput = str(output, 'UTF-8')

#sending packets
tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
if(tcp_connect_scan_resp.haslayer(TCP)):
    if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
        send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
        print("[*] Port 80 is Open")
        print("[*] Possibly a web server running on " + IP)
    elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
        print ("[*] Port 80 is closed, trying port 443")
        dst_port = 443
        tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
			if(tcp_connect_scan_resp.haslayer(TCP)):
				if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
					send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
					print("[*] Port 443 is Open")
					sleep(0.5)
					print("[*] Possibly a web server running on " + IP)
					webservertests()
				elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
					print ("[*] Both Port 80 and Pory 443 are closed on " + IP)

