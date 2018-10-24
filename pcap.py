#coding=utf-8
import dpkt
import re
import hashlib
def getaddr(origin):
    if len(origin) !=4:
        print "addr len error"
        return None
    return str(ord(origin[0])) + '.' + str(ord(origin[1]))+ '.' + str(ord(origin[2]))+ '.' + str(ord(origin[3]))

def getport(origin):
    if len(origin) !=2:
        print "prot len error"
        return None
    return str(ord(origin[0])*16*16 + ord(origin[1]))

f = open('1.pcap','rb')
pcaps = dpkt.pcap.Reader(f)
all_info = []
for buf in pcaps:
    pcap_info = {}
    if ord(buf[1][23]) != 6:
        continue

    #proto = getaddr(buf[1][24])    #proto
    src_ip = getaddr(buf[1][26:30]) #src_ip
    drt_ip = getaddr(buf[1][30:34]) #drt ip
    src_port = getport(buf[1][34:36]) #src port
    drt_port = getport(buf[1][36:38]) #drt port
    src_ip_port = src_ip + ':' + src_port
    drt_ip_port = drt_ip + ':' + drt_port
    pcap_info[src_ip_port] = 'OK'
    pcap_info[drt_ip_port] = 'OK'

    if pcap_info not in all_info:
        all_info.append(pcap_info)

a = {'10.0.2.15:52319': 'OK', '104.28.1.207:80': 'OK'}
b = {'104.28.1.207:80': 'OK', '10.0.2.15:52319': 'OK'}
if a == b:
    print 'equal'
else:
    print 'not equal'

    host = re.findall(r'\r\nHost: (.*)\r\n',buf[1])
    #host = re.findall(r'\r\nHost: (.*)\r\n',buf[1])
    #print host
