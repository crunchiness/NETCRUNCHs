#!/usr/bin/env python
__author__ = 'Ingvaras Merkys'

import binascii
import csv
import argparse
from pcapfile import savefile
from pcapfile.protocols.network.ip import IP
from pcapfile.protocols.linklayer.ethernet import Ethernet
from timestamp import TimeStamp

# field names of output file
FIELD_NAMES = ['timestamp', 'v', 'hl', 'tos', 'len', 'id', 'flags', 'off', 'ttl', 'protocol', 'sum', 'src', 'dst',
               'opt', 'pad', 'website', 'source', 'is_ack', 'is_rst', 'is_fin', 'url', 'src_port', 'dst_port']


def parse(ip_packet):
    """Parses IP packet"""
    protocols = {
        0: 'HOPOPT',
        1: 'ICMP',
        2: 'IGMP',
        3: 'GGP',
        4: 'IP-in-IP',
        5: 'ST',
        6: 'TCP',
        7: 'CBT',
        8: 'EGP',
        9: 'IGP',
        10: 'BBN-RCC-MON',
        11: 'NVP-II',
        12: 'PUP',
        13: 'ARGUS',
        14: 'EMCON',
        15: 'XNET',
        16: 'CHAOS',
        17: 'UDP',
        18: 'MUX',
        19: 'DCN-MEAS',
        20: 'HMP',
        21: 'PRM',
        22: 'XNS-IDP',
        23: 'TRUNK-1',
        24: 'TRUNK-2',
        25: 'LEAF-1',
        26: 'LEAF-2',
        27: 'RDP',
        28: 'IRTP',
        29: 'ISO-TP4',
        30: 'NETBLT',
        31: 'MFE-NSP',
        32: 'MERIT-INP',
        33: 'DCCP',
        34: '3PC',
        35: 'IDPR',
        36: 'XTP',
        37: 'DDP',
        38: 'IDPR-CMTP',
        39: 'TP++',
        40: 'IL',
        41: 'IPv6',
        42: 'SDRP',
        43: 'IPv6-Route',
        44: 'IPv6-Frag',
        45: 'IDRP',
        46: 'RSVP',
        47: 'GRE',
        48: 'MHRP',
        49: 'BNA',
        50: 'ESP',
        51: 'AH',
        52: 'I-NLSP',
        53: 'SWIPE',
        54: 'NARP',
        55: 'MOBILE',
        56: 'TLSP',
        57: 'SKIP',
        58: 'IPv6-ICMP',
        59: 'IPv6-NoNxt',
        60: 'IPv6-Opts',
        62: 'CFTP',
        64: 'SAT-EXPAK',
        65: 'KRYPTOLAN',
        66: 'RVD',
        67: 'IPPC',
        69: 'SAT-MON',
        70: 'VISA',
        71: 'IPCU',
        72: 'CPNX',
        73: 'CPHB',
        74: 'WSN',
        75: 'PVP',
        76: 'BR-SAT-MON',
        77: 'SUN-ND',
        78: 'WB-MON',
        79: 'WB-EXPAK',
        80: 'ISO-IP',
        81: 'VMTP',
        82: 'SECURE-VMTP',
        83: 'VINES',
        84: 'TTP/IPTM',
        85: 'NSFNET-IGP',
        86: 'DGP',
        87: 'TCF',
        88: 'EIGRP',
        89: 'OSPF',
        90: 'Sprite-RPC',
        91: 'LARP',
        92: 'MTP',
        93: 'AX.25',
        94: 'IPIP',
        95: 'MICP',
        96: 'SCC-SP',
        97: 'ETHERIP',
        98: 'ENCAP',
        100: 'GMTP',
        101: 'IFMP',
        102: 'PNNI',
        103: 'PIM',
        104: 'ARIS',
        105: 'SCPS',
        106: 'QNX',
        107: 'A/N',
        108: 'IPComp',
        109: 'SNP',
        110: 'Compaq-Peer',
        111: 'IPX-in-IP',
        112: 'VRRP',
        113: 'PGM',
        115: 'L2TP',
        116: 'DDX',
        117: 'IATP',
        118: 'STP',
        119: 'SRP',
        120: 'UTI',
        121: 'SMP',
        122: 'SM',
        123: 'PTP',
        124: 'IS-IS over IPv4',
        125: 'FIRE',
        126: 'CRTP',
        127: 'CRUDP',
        128: 'SSCOPMCE',
        129: 'IPLT',
        130: 'SPS',
        131: 'PIPE',
        132: 'SCTP',
        133: 'FC',
        134: 'RSVP-E2E-IGNORE',
        135: 'Mobility Header',
        136: 'UDPLite',
        137: 'MPLS-in-IP',
        138: 'manet',
        139: 'HIP',
        140: 'Shim6',
        141: 'WESP',
        142: 'ROHC'
    }

    try:
        protocol = protocols[ip_packet.p]
    except KeyError:
        protocol = 'UNKNOWN'

    return {
        'v': ip_packet.v,
        'hl': ip_packet.hl,
        'tos': ip_packet.tos,
        'len': ip_packet.len,
        'id': ip_packet.id,
        'flags': ip_packet.flags,
        'off': ip_packet.off,
        'ttl': ip_packet.ttl,
        'protocol': protocol,
        'sum': ip_packet.sum,
        'src': ip_packet.src,
        'dst': ip_packet.dst,
        'opt': ip_packet.opt,
        'pad': ip_packet.pad
    }


def get_pcap_time_limits(packets):
    """"Gets accurate time limits of PCAP data"""
    timestamp_pcap_from = float('inf')
    timestamp_pcap_to = 0
    for pkt in packets:
        pkt_timestamp = pkt.timestamp + pkt.timestamp_ms / 1000000.
        if pkt_timestamp < timestamp_pcap_from:
            timestamp_pcap_from = pkt_timestamp
        if pkt_timestamp > timestamp_pcap_to:
            timestamp_pcap_to = pkt_timestamp
    return timestamp_pcap_from, timestamp_pcap_to


def get_tcp_flags(ip_packet):
    tcp_packet = binascii.unhexlify(ip_packet.payload)
    return ord(tcp_packet[13])


def is_ack(pkt_obj, ip_packet):
    if pkt_obj['protocol'] == 'TCP':
        tcp_packet = binascii.unhexlify(ip_packet.payload)

        # extract data offset in words and multiply by 4 to get in bytes
        tcp_header_bytes = int(bin(ord(tcp_packet[12]))[2:].zfill(8)[:4], 2) * 4

        # check if ack flag is set
        flags = get_tcp_flags(ip_packet)
        ack_mask = int('00010000', 2)
        ack_set = (ack_mask & flags) == ack_mask

        # if ack mask set and there is no payload, it's an ACK
        return ack_set and len(tcp_packet) == tcp_header_bytes
    else:
        return False


def is_fin(pkt_obj, ip_packet):
    if pkt_obj['protocol'] == 'TCP':
        flags = get_tcp_flags(ip_packet)
        fin_mask = int('00000001', 2)
        fin_set = (fin_mask & flags) == fin_mask
        return fin_set
    else:
        return False


def is_rst(pkt_obj, ip_packet):
    if pkt_obj['protocol'] == 'TCP':
        flags = get_tcp_flags(ip_packet)
        rst_mask = int('00000100', 2)
        rst_set = (rst_mask & flags) == rst_mask
        return rst_set
    else:
        return False


def get_ports(pkt_obj, ip_packet):
    if pkt_obj['protocol'] == 'TCP':
        tcp_packet = binascii.unhexlify(ip_packet.payload)
        src_port = (ord(tcp_packet[0]) << 8) and ord(tcp_packet[1])
        dst_port = (ord(tcp_packet[2]) << 8) and ord(tcp_packet[3])
        return src_port, dst_port
    else:
        return -1, -1


def parse_pcap(packets, timestamp_abs_from=None, timestamp_abs_to=None, website=None, source=None, write_csv=False,
               csv_name='dump.csv'):
    """
    Produces Python list from PCAP file. In addition to parsed fields adds 'is_ack', 'is_rst', 'is_fin', 'timestamp',
    'src_port', 'dst_port', 'source', and 'website' (last two are empty sets).
    Filters out packets to/from 127.0.0.1 and 127.0.1.1
    :param packets:
    :param timestamp_abs_from:
    :param timestamp_abs_to:
    :param write_csv:
    :param csv_name:
    :return:
    """
    timestamp_abs_from = 0 if timestamp_abs_from is None else timestamp_abs_from.get_seconds()
    timestamp_abs_to = float('inf') if timestamp_abs_to is None else timestamp_abs_to.get_seconds()
    pcap_list = []
    writer = None
    csv_file = None
    if write_csv:
        csv_file = open(csv_name, 'w')
        writer = csv.DictWriter(csv_file, fieldnames=FIELD_NAMES)
        writer.writeheader()
    for pkt in packets:
        pkt_ts = pkt.timestamp + pkt.timestamp_ms / 1000000.
        if timestamp_abs_from < pkt_ts < timestamp_abs_to:
            eth_frame = Ethernet(pkt.raw(), sll=True)
            ip_packet = IP(binascii.unhexlify(eth_frame.payload))
            pkt_obj = parse(ip_packet)
            pkt_obj['is_ack'] = is_ack(pkt_obj, ip_packet)
            pkt_obj['is_rst'] = is_rst(pkt_obj, ip_packet)
            pkt_obj['is_fin'] = is_fin(pkt_obj, ip_packet)
            pkt_obj['timestamp'] = pkt_ts
            pkt_obj['src_port'], pkt_obj['dst_port'] = get_ports(pkt_obj, ip_packet)
            pkt_obj['source'] = set([]) if source is None else source
            pkt_obj['website'] = set([]) if website is None else website
            if not (pkt_obj['src'] in ['127.0.0.1', '127.0.1.1'] or pkt_obj['dst'] in ['127.0.0.1', '127.0.1.1']):
                pcap_list.append(pkt_obj)
                if write_csv:
                    writer.writerow(pkt_obj)
    if write_csv:
        csv_file.close()
    return pcap_list


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Produces CSV from PCAP file.')
    parser.add_argument('pcap_name', nargs='?', type=str, help='input PCAP file (\'dump.pcap\' by default)',
                        default='dump.pcap')
    args = parser.parse_args()
    file_name = args.pcap_name
    out_name = file_name[:-5] + '.csv'
    pcap_file = open(file_name)
    pcap_data = savefile.load_savefile(pcap_file, verbose=True)
    time_from, time_to = get_pcap_time_limits(pcap_data.packets)
    parse_pcap(pcap_data.packets, TimeStamp(time_from), TimeStamp(time_to), write_csv=True, csv_name=out_name)
    pcap_file.close()
