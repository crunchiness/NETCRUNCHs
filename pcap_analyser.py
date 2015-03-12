# -*- coding: utf-8 -*-
__author__ = 'crunch'
import binascii
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


def get_pcap_time_limits(packets):
    timestamp_pcap_from = float('inf')
    timestamp_pcap_to = 0
    for pkt in packets:
        pkt_timestamp = pkt.timestamp + pkt.timestamp_ms / 1000000.
        if pkt_timestamp < timestamp_pcap_from:
            timestamp_pcap_from = pkt_timestamp
        if pkt_timestamp > timestamp_pcap_to:
            timestamp_pcap_to = pkt_timestamp
    return timestamp_pcap_from, timestamp_pcap_to