# -*- coding: utf-8 -*-
__author__ = 'crunch'
import json
import argparse
import binascii
from pcapfile import savefile
from pcapfile.protocols.network.ip import IP
from pcapfile.protocols.linklayer.ethernet import Ethernet
from json_analyser import get_json_time_limits, preprocess_json
from pcap_analyser import get_pcap_time_limits
from timestamp import TimeStamp


def get_abs_time_limits(ts1_from, ts1_to, ts2_from, ts2_to):
    """Finds overlap between two time intervals"""
    if ts1_from > ts2_from:
        t_min_from = ts1_from
    else:
        t_min_from = ts2_from
    if ts1_to < ts2_to:
        t_min_to = ts1_to
    else:
        t_min_to = ts2_to
    return t_min_from, t_min_to


def produce_statistics(json_data, pcap_data, time_from, time_to):
    """"""
    tolerance = 0.1  # in seconds
    statistics = {}
    for website in json_data:
        statistics[website] = {}
        for i, pair in enumerate(json_data[website]):
            req_timestamp = pair['request']['timeStamp'] / 1000.
            if not time_from.get_seconds() < req_timestamp < time_to.get_seconds():
                continue
            statistics[website][i] = 0
            ip = pair['response']['ip']
            for pkt in pcap_data:
                pkt_timestamp = pkt.timestamp + pkt.timestamp_ms / 1000000.
                if not req_timestamp <= pkt_timestamp < req_timestamp + tolerance:
                    continue
                eth_frame = Ethernet(pkt.raw())
                ip_packet = IP(binascii.unhexlify(eth_frame.payload))
                if ip_packet.dst == ip:
                    statistics[website][i] += 1
    summarized_stats = {}
    for website in statistics:
        summarized_stats[website] = {}
        for key in statistics[website]:
            try:
                summarized_stats[website][statistics[website][key]] += 1
            except KeyError:
                summarized_stats[website][statistics[website][key]] = 1
    # f = open('one-maximize.txt', 'a')
    # for website in summarized_stats:
    #     try:
    #         good_matches = summarized_stats[website][1]
    #     except KeyError:
    #         good_matches = 0
    #     try:
    #         zero_matches = summarized_stats[website][0]
    #     except KeyError:
    #         zero_matches = 0
    #     multiple_matches = 0
    #     for key in summarized_stats[website]:
    #         if key > 1:
    #             multiple_matches += summarized_stats[website][key]
    #     f.write('{0},{1},{2},{3},{4}\n'.format(website, tolerance, good_matches, zero_matches, multiple_matches))
    # f.close()
    print summarized_stats


def main(json_name, pcap_name, preprocessed):
    """Main method"""
    json_file = open(json_name)
    pcap_file = open(pcap_name)
    if preprocessed:
        json_data = json.load(json_file)
    else:
        raw_json_data = json.load(json_file)
        json_data = preprocess_json(raw_json_data)
    pcap_data = savefile.load_savefile(pcap_file, verbose=True)
    timestamp_json_from, timestamp_json_to = get_json_time_limits(json_data)
    timestamp_pcap_from, timestamp_pcap_to = get_pcap_time_limits(pcap_data.packets)
    timestamp_abs_from, timestamp_abs_to = get_abs_time_limits(timestamp_json_from, timestamp_json_to,
                                                               TimeStamp(timestamp_pcap_from),
                                                               TimeStamp(timestamp_pcap_to))
    # for i in xrange(100):
    #     print i
    #     produce_statistics(json_data, pcap_data.packets, timestamp_abs_from, timestamp_abs_to, i/1000.)

    # print 'timestamp_abs_from', timestamp_abs_from.get_datetime()
    # print 'timestamp_abs_to', timestamp_abs_to.get_datetime()

    produce_statistics(json_data, pcap_data.packets, timestamp_abs_from, timestamp_abs_to)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Description.')
    parser.add_argument('-p', '--preprocessed', help='use preprocessed JSON',
                        action='store_true')
    parser.add_argument('json_name', nargs='?', type=str, help='input JSON file')
    parser.add_argument('pcap_name', nargs='?', type=str, help='input PCAP file', default='dump.pcap')

    args = parser.parse_args()

    if args.json_name is None:
        if args.preprocessed:
            args.json_name = 'data_preprocessed.json'
        else:
            args.json_name = 'data.json'

    main(args.json_name, args.pcap_name, args.preprocessed)