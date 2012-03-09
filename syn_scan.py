# syn_scan.py
# description: simple sync scan using scapy
from scapy.all import *
from ssh_exceptions import *
import socket

def check_port(host,port):
    try:
        req = IP(dst=host)/TCP(dport=port,flags='S')
        res = sr1(req,verbose=0)
        return (res.haslayer(TCP) and res[TCP].flags == 18)
    except socket.error, (errno, msg):
        if errno == 1:
            raise NotRoot('gotta be root to do da ping!!!')
        raise