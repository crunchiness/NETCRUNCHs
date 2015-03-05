__author__ = 'crunch'
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
import binascii
testcap = open('samples/test.pcap')
capfile = savefile.load_savefile(testcap, verbose=True)
eth_frame = ethernet.Ethernet(capfile.packets[0].raw())

print eth_frame
# ethernet from 00:11:22:33:44:55 to ff:ee:dd:cc:bb:aa type IPv4
ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))
print ip_packet
# ipv4 packet from 192.168.2.47 to 173.194.37.82 carrying 44 bytes ~~~~
