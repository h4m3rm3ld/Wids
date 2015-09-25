#!/usr/bin/env python
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess
import argparse
ap_list = {}
ap_permit = []
ssid_permit = []
log="/var/log/wids"
def jump(ch):
	out = subprocess.check_output(['iw','dev','wlan0mon','set','channel',str(ch)])
def log(reg):
	file = open("/var/log/wids",'a')
	file.write("{0}\n".format(reg))
	file.close()
def PacketHandler(pkt) :
  global i
  global ch
  if i==5:
  	if ch==14:
		ch=1
	else:  
		jump(ch)
		i=0
		ch=ch+1
  else:
	i=i+1  
  if pkt.haslayer(Dot11):
 	if pkt.type == 0:
		if pkt.subtype == 8 :
			if pkt.addr2 not in ap_list :
				ap_list[pkt.addr2]=pkt.info
				apmac=pkt.addr2
				ssid=pkt.info
				
				if str(apmac) not in ap_permit or str(ssid) not in ssid_permit:
					line="[ALERT] {2} AP MAC: {0} SSID: {1}".format(apmac, ssid, str(time.strftime("%c")))
					log(line)
					if args.verbose == 1:
						print line
				else: 
					line="[INFO] {2} AP MAC: {0} with SSID: {1} ".format(pkt.addr2, pkt.info, str(time.strftime("%c")))
					log(line)
					if args.verbose == 1:
						print line
		if pkt.subtype == 12 :
			line="[ALERT] {2} Deauth BSSID:{0} ESSID:{1}".format(pkt.addr2, ap_list[pkt.addr2], str(time.strftime("%c")))
			log(line)
			if args.verbose == 1:
				print line
		if pkt.subtype == 4:
			line="[INFO] {2} Paquete probe ESSID: {0} MAC: {1}".format(pkt.info, pkt.addr2, str(time.strftime("%c")))
			log(line)
			if args.verbose == 1:
				print line

parser = argparse.ArgumentParser()
parser.add_argument('-v', action='count', dest='verbose')
args=parser.parse_args()
global i
i=0
global ch
ch=1
sniff(iface="wlan0mon", prn = PacketHandler)
