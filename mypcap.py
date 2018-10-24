import dpkt
import socket
f = open('1.pcap')
pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:
        print ts, len(buf)
        print '\r\n'
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        #print help(ip)
        print socket.inet_ntoa(ip.src)
        print socket.inet_ntoa(ip.dst)
        print (tcp.sport)
        print tcp.dport
        print '\r\n'
