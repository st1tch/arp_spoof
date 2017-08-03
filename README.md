# arp_spoofing

## Environment
* OS : Ubuntu 16.04 64bit </br>
* Language : python 2.7.12 </br>
* Requirements
> python - scapy module 

## Homework
* [리포트]
> arp spoofing 프로그램을 구현하라.</br>
victim(sender)에서 gilgil.net 사이트 로그인할 때의 패킷을 attacker에서 잡아 볼 수 있다면 과제 완료.</br>

* [프로그램]
> arp_spoof &lt;interface&gt; &lt;sender ip 1&gt; &lt;target ip 1&gt; [&lt;sender ip 2&gt; &lt;target ip 2&gt;...] </br>
> ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2 </br>
> sender ip는 victim ip, target ip는 일반적으로 gateway임.</br>


* [학습] 
```
지난번 과제를 완료를 해야만 본 과제를 진행할 수 있음.
오늘 배운 "ARP spoofing의 모든 것" PPT 숙지할 것.
```


## ARP headers
- ARP header
![1](https://github.com/st1tch/arp_test/blob/master/arp_header.png)
</br>

## Reference
- 
