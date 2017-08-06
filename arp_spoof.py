#!/usr/bin/python
#-*- coding: utf-8 -*-

import subprocess
import sys
import re
import struct
from threading import *
from time import sleep
from pwn import hexdump
from socket import *

execmd = lambda cmd : subprocess.check_output(cmd, shell=True)
trans_ip = lambda addr : ''.join(map(lambda x:chr(eval(x)), addr.split('.')))
trans_mac = lambda mac : ''.join(map(lambda x:x.decode('hex'), mac.split(':')))

p16 = lambda x : struct.pack('>H', x)
p32 = lambda x : struct.pack('>I', x)

ip_regex = ('[\d]{1,3}.'*4)[:-1]
mac_regex = ('[0-9a-f]{2}:'*6)[:-1]

'''
Send packet
'''
def sendeth(dst, src, type, payload):
    pkt = trans_mac(dst)
    pkt += trans_mac(src)
    pkt += p16(type)
    pkt += payload

    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((sys.argv[1], 0))
    print hexdump(pkt)
    s.send(pkt)
    
'''
Make arp packet
'''
def make_arp(hwtype, ptype, hwlen, plen, oper, snd_mac, snd_ip, tar_mac, tar_ip):
    pkt = ''
    pkt += p16(hwtype)
    pkt += p16(ptype)
    pkt += chr(hwlen)
    pkt += chr(plen)
    if oper == 'req':
        pkt += p16(0x1)
    elif oper == 'reply':
        pkt += p16(0x2)
    pkt += trans_mac(snd_mac)
    pkt += trans_ip(snd_ip)
    pkt += trans_mac(tar_mac)
    pkt += trans_ip(tar_ip)
    return pkt

'''
Receive packet
'''
def recv_pkt(proto_type):
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    while True:
        tmp = s.recvfrom(65535)
        eth_dstmac = tmp[:6]
        eth_srcmac = tmp[6:12]
        eth_type = tmp[12:14]
        if eth_type == ARP:
            arp_pkt = eth_

        elif eth_type == IP:


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
    eth_dstmac = 'ff:ff:ff:ff:ff:ff'
    eth_srcmac = my_mac
    arp_sndmac = my_mac       
    arp_sndip = my_ip
    arp_tarmac = '00:00:00:00:00:00'
    arp_tarip = ip_addr
    pay = make_arp(0x1, 0x0800, 0x6, 0x4, 'req', arp_sndmac, arp_sndip, arp_tarmac, arp_tarip)
    sendeth(eth_srcmac, eth_dstmac, 0x0806, pay)
    recv_pkt()


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

    get_macaddr(sender_ip[0])
    '''
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
        print '[*] TARGET{} THREAD START!'.format(idx+1)
        Thread(target=ARP_reply, args=(idx,)).start() 

    while(1):
        sleep(5)
    '''
