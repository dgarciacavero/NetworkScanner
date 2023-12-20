#!/usr/bin/env python3
import scapy.all as scapy
import re
import argparse
import os
import sys

def CheckSudo():
    if os.getuid() != 0:
        print("\nProgram must be run with root privileges!!")
        sys.exit(1)

def CreateParser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip", help="IP Address to scan")
    parser.add_argument("-n", "--network_mask", dest="network_mask", help="Network mask if you want to scan a whole network")
    return parser.parse_args()

def GetAddress(options):
    if options.ip is None:
        print("\n[-]Please specify an IP address. Use -h or --help for more information.")
        sys.exit(1)
    else:
        if options.network_mask is None:
            return options.ip
        else:
            return options.ip + "/" + options.network_mask

#Create an ARP request directed to broadcast 
def CreatePacket(ip):
    ARP_packet = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    return broadcast/ARP_packet
    
#Send the packet and wait for responses
def Send(packet):
    answered = scapy.srp(packet, timeout=1, verbose=False)[0]
    dicc = {}
    for r in answered:
        dicc.update({r[1].psrc : r[1].hwsrc})
    return dicc

#Print the results
def PrintResults(dicc):
    print("IP\t\t\tMAC")
    print("=========================================")
    for ip in dicc.keys():
        print(ip + "\t\t" + dicc.get(ip))
        print("-----------------------------------------")

try:
    CheckSudo()
    options = CreateParser()
    ip = GetAddress(options)
    print("\n[+] Scanning " + ip +" ...\n")
    packet = CreatePacket(ip)
    dicc = Send(packet)
    PrintResults(dicc)
except KeyboardInterrupt:
    print('\n[-] CTRL+C detected. Exiting...')
    sys.exit(0)