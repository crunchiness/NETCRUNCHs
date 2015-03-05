# -*- coding: utf-8 -*-
__author__ = 'crunch'
import json
import binascii
from pcapfile import savefile
from pcapfile.protocols.network.ip import IP
from pcapfile.protocols.linklayer.ethernet import Ethernet


def parse(ip_packet):
    return {
        'v': ip_packet.v,
        'hl': ip_packet.hl,
        'tos': ip_packet.tos,
        'len': ip_packet.len,
        'id': ip_packet.id,
        'flags': ip_packet.flags,
        'off': ip_packet.off,
        'ttl': ip_packet.ttl,
        'p': ip_packet.p,
        'sum': ip_packet.sum,
        'src': ip_packet.src,
        'dst': ip_packet.dst,
        'opt': ip_packet.opt,
        'pad': ip_packet.pad,
        # 'payload': ip_packet.payload
    }


f = open('data.json')
data = json.load(f)
if 'www.tumblr.com' not in data.keys():
    print 'No tumblr found.'

testcap = open('dump.pcap')
capfile = savefile.load_savefile(testcap, verbose=True)

total = 0
zero = 0
one = 0
two = 0
three = 0
more = 0
for pair in data['www.tumblr.com']['pairs']:
    try:
        timestamp = pair['request']['timeStamp'] / 1000
    except KeyError:
        continue
    except TypeError:
        continue
    timestamp_from = timestamp
    timestamp_to = timestamp + 0.02
    try:
        ip = pair['response']['ip']
    except KeyError:
        continue
    except TypeError:
        continue
    results = []
    for pkt in capfile.packets:
        eth_frame = Ethernet(pkt.raw())
        ip_packet = IP(binascii.unhexlify(eth_frame.payload))
        if ip_packet.dst == ip:
            pkt_timestamp = pkt.timestamp + pkt.timestamp_ms / 1000000.
            if timestamp_from < pkt_timestamp < timestamp_to:
                results.append(parse(ip_packet))
    if len(results) == 0:
        zero += 1
    elif len(results) == 1:
        one += 1
    elif len(results) == 2:
        two += 1
    elif len(results) == 3:
        three += 1
    else:
        more += 1
    total += 1
print 'Total:', total
print 'zero', zero
print 'one:', one
print 'two', two
print 'three', three
print 'more', more