#!/usr/bin/python
#-*- coding: utf-8 -*-

import subprocess
import sys
import re
from threading import *
from time import sleep
from scapy.all import *

execmd = lambda cmd : subprocess.check_output(cmd, shell=True)
ip_regex = ('[\d]{1,3}.'*4)[:-1]
mac_regex = ('[0-9a-f]{2}:'*6)[:-1]

'''
Get my mac,ip address 
'''
def getMyAddr(dev):
    tmp = execmd('ifconfig | grep {} -A 10'.format(dev))
    my_ip = re.findall(ip_regex, tmp)[0]
    my_mac = re.findall(mac_regex, tmp)[0]
    return my_mac, my_ip

'''
Get mac address using ip address
'''
def get_macaddr(ip_addr):
    eth_srcmac = my_mac
    eth_dstmac = 'ff:ff:ff:ff:ff:ff'
    arp_srcip = ip_addr
    arp_srcmac = '00:00:00:00:00:00'
    arp_dstip = my_ip
    arp_dstmac = my_mac       
    reqPacket = Ether(src=eth_srcmac, dst=eth_dstmac, type=0x0806)/ARP(pdst=arp_srcip, psrc=arp_dstip, hwsrc=arp_dstmac, ptype=0x0800, hwtype=1, hwlen=6, plen=4, op=ARP.who_has)
    return srp(reqPacket)
    


if __name__ == '__main__':
    # Check args
    if (len(sys.argv) < 4) or (len(sys.argv) % 2):
        print '[!] Usage : python arp_spoof.py <interface> <sender ip1> <target ip1> [<sender ip2> <target ip2> ...]'
        exit()

    #-------------
    my_ip = ''        
    my_mac = ''       
    sender_ip = ''        
    sender_mac = ''       
    target_mac = ''       
    target_ip = ''        
    eth_srcmac=''   
    eth_dstmac=''
    arp_srcip=''
    arp_srcmac=''
    arp_dstip=''
    arp_dstmac=''
    #-------------

    print '[+] Get Address ...'
    ifname = sys.argv[1]
    sender_ip = sys.argv[2]
    target_ip = sys.argv[3]
    my_mac, my_ip = getMyAddr(ifname)

    print '[+] Send request packet for sender mac address...'
    sender_mac = get_macaddr(sender_ip)[0][0][1].src
    target_mac = get_macaddr(target_ip)[0][0][1].src

    print '[*]', 'INFORMATION'.center(30, '-')
    print 'MY IP'.ljust(10, ' '),': {}'.format(my_ip)
    print 'MY MAC'.ljust(10, ' '), ': {}'.format(my_mac)
    print 'SENDER IP'.ljust(10, ' '), ': {}'.format(sender_ip)
    print 'SENDER MAC'.ljust(10, ' '), ': {}'.format(sender_mac)
    print 'TARGET IP'.ljust(10, ' '), ': {}'.format(target_ip)
    print 'TRAGET MAC'.ljust(10, ' '), ': {}'.format(target_mac)
    print '-'*34
    
    raw_input('stop')

    #-------- Thread sniff and reply
    Thread(target=arp_poision, args=('reply',))
    Thread(target=arp_poision, args=('poision',))

    while(1):
        time.sleep(5)
