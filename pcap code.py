__author__ = 'Deepak Hariharan'
#Deep Packet Analyzer that analyzes PCAP files for Different Protocols
import pcap
import dpkt
import binascii
import socket
import datetime
import struct
import Tkinter, tkFileDialog

root = Tkinter.Tk()
root.withdraw()

file_path = tkFileDialog.askopenfilename()
import string
from struct import unpack


def get_message_segment_size (options ) :
    """get the maximum segment size from the options list"""
    options_list = dpkt.tcp.parse_opts ( options )
    for option in options_list :
        if option[0] == 2 :
# The MSS is a 16 bit number   dpkt decodes it as a 16
# bit number.  An MSS is never going to be bigger than 65496 bytes.
# The most common value is 1460 bytes (IPv4) which 0x05b4 or 1440 bytes (IPv6) which is 0x05a0.  The format string ">H" means
# big-endian unsigned 16 bit number.  It should be ">L" which is big-endian 32 bit number.
            mss = struct.unpack(">H", option[1])
            return mss


def add_colons_to_mac( mac_addr ) :
    """This function accepts a 12 hex digit string and converts it to a colon separated string"""
    s = list()
    for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append(mac_addr[i*2:i*2+2] )
    r = ":".join(s)
    return r

#print dir(dpkt.icmp6.ICMP6)

f = open(file_path)
pcap = dpkt.pcap.Reader(f)
i=1
for ts, buf in pcap:
    print "------------------------------------------------------------------------------------------------"
    print '\033[1m' + "The details for Frame no. %d" % i +'\033[0m'
    print "The Data Link Layer Details:"
    ethpkt = dpkt.ethernet.Ethernet(buf)
    #####################################################################ETHERNET LAYER##########
    #print dir(ethpkt)
    capturedate = datetime.datetime.fromtimestamp(float(ts)).strftime('%d-%m-%Y')
    capturetime = datetime.datetime.fromtimestamp(float(ts)).strftime('%T')
    print "The Ethernet frame was captured on %s at %s" % (capturedate, capturetime)
    ethlen=ethpkt.__len__()
    print "Ethernet frame length : %d | " % ethlen,
    hexdestmac = binascii.hexlify(ethpkt.dst)
    print "theeeeeeeeeeeeeeeeeeeeeeeeeeeee" +hexdestmac
    hexdestmac = add_colons_to_mac(hexdestmac)
    hexsrcmac = binascii.hexlify(ethpkt.src)
    hexsrcmac = add_colons_to_mac(hexsrcmac)
    hexethtype = hex(ethpkt.type)
    if hexethtype == "0x800":
        print "Ethernet type : IP(%s)" % hexethtype
    elif hexethtype == 0x86dd:
        print "Ethernet type : IPv6(%s)" % hexethtype
    print "Source MAC address : %s | " % hexsrcmac,
    print "Destination MAC address : %s" % hexdestmac
    print hexethtype
    ########################################################################IP LAYER##################
    print "\nThe Network Layer Details"
    ethdata = ethpkt.data
    if hexethtype == "0x800":
        dst_ip_addr_str = socket.inet_ntoa(ethdata.dst)
        src_ip_addr_str = socket.inet_ntoa(ethdata.src)
        iplen = ethdata.len
        ipheaderlen = ethdata.__hdr_len__
        ipver = ethdata.v
        ipproto = ethdata.p
        ipident = ethdata.id
        print "Version : IPv%s" % ipver
        print "Source IP address : %s" % src_ip_addr_str
        print "Destination IP address : %s" % dst_ip_addr_str
        print "Header Length : %d" % ipheaderlen
        print "Total length : %d" % iplen
        print "Identification : %s(%s)" % (hex(ipident),ipident)
        print "Time to live : %s" %ethdata.ttl
        print "Header Checksum : %s" %hex(ethdata.sum)
        print "Offset : %s" %ethdata.off
        if ipproto == 6:
            print "Protocol : TCP(%s)" % ipproto
        elif ipproto == 17:
            print "Protocol : UDP(%s)" % ipproto
        #print dir(ethdata)
        ipdata=ethdata.data

    elif hexethtype == 0x86dd:
        print hexethtype
        dst_ip6_addr_str = socket.inet_pton(socket.AF_INET6, "2001:1938:26f:1:204:4bff:0:1")
        print dst_ip6_addr_str
        #src_ip6_addr_str = socket.inet_ntoa(ethdata.src)

    ########################################################################TRANSPORT LAYER##################
    print "\nThe Transport Layer Details"

    destport = ipdata.dport
    srcport = ipdata.sport
    try:
        print "Source Port : %s (%s) |" %(socket.getservbyport(srcport),srcport),
    except:
        print "Source Port : %s |" %srcport,

    try :
        print "Destination Port : %s (%s)" %(socket.getservbyport(destport),destport)
    except:
        print "Destination Port : %s" %destport

   # print dir(ipdata)
   # print ipdata.opts
    print "IPproto is %s" %ipproto
    if ipproto == 6:
        ipmss = get_message_segment_size(ipdata.opts)
        print ipmss
        fin_flag = ( ipdata.flags & dpkt.tcp.TH_FIN ) != 0
        syn_flag = ( ipdata.flags & dpkt.tcp.TH_SYN ) != 0
        rst_flag = ( ipdata.flags & dpkt.tcp.TH_RST ) != 0
        psh_flag = ( ipdata.flags & dpkt.tcp.TH_PUSH) != 0
        ack_flag = ( ipdata.flags & dpkt.tcp.TH_ACK ) != 0
        urg_flag = ( ipdata.flags & dpkt.tcp.TH_URG ) != 0
        ece_flag = ( ipdata.flags & dpkt.tcp.TH_ECE ) != 0
        cwr_flag = ( ipdata.flags & dpkt.tcp.TH_CWR ) != 0
        flags=(fin_flag,syn_flag,rst_flag,psh_flag,ack_flag,urg_flag,ece_flag,cwr_flag)
        flags_str=('fin_flag','syn_flag','rst_flag','psh_flag','ack_flag','urg_flag','ece_flag','cwr_flag')
        print "Flags :"
        for j in range(0,8):
            if flags[j] is True:
                print "     %s : Set" % flags_str[j]
            elif flags[j] is False:
                print "     %s : Not Set" % flags_str[j]
    i = i+1