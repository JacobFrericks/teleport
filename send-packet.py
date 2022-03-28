from scapy.all import *


def send_packet():
    iface = "en0"
    sendp(IP(dst="192.168.100.123", src="192.168.86.42")/TCP(sport=333, dport=222, seq=112344)/"Sequence number 112344", iface=iface)
    sendp(IP(dst="192.168.100.123", src="192.168.86.42")/TCP(sport=333, dport=223, seq=112344)/"Sequence number 112344", iface=iface)
    sendp(IP(dst="192.168.100.123", src="192.168.86.42")/TCP(sport=333, dport=224, seq=112344)/"Sequence number 112344", iface=iface)
    sendp(IP(dst="192.168.100.123", src="192.168.86.42")/TCP(sport=333, dport=225, seq=112344)/"Sequence number 112344", iface=iface)
    sendp(IP(dst="192.168.100.123", src="192.168.86.42")/TCP(sport=333, dport=226, seq=112344)/"Sequence number 112344", iface=iface)
    # lsc() can see functions descriptions.


if __name__ == "__main__":
    send_packet()
