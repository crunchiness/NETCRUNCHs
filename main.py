# -*- coding: utf-8 -*-
__author__ = 'crunch'
import json
import csv
import argparse
import binascii
from pcapfile import savefile
from pcapfile.protocols.network.ip import IP
from pcapfile.protocols.linklayer.ethernet import Ethernet
from json_analyser import get_json_time_limits, preprocess_json, preprocess_time_tab_data
from pcap_analyser import get_pcap_time_limits, parse_pcap
from timestamp import TimeStamp

ips = {}


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


def req_pkt_stats(json_data, pcap_data, time_from, time_to):
    """Request-packet matching"""
    tolerance = 0.01  # in seconds
    statistics = {}
    for website in json_data:
        statistics[website] = {}
        for i, pair in enumerate(json_data[website]):
            req_timestamp = pair['request']['timeStamp'] / 1000.
            if not time_from.get_seconds() < req_timestamp < time_to.get_seconds():
                continue
            statistics[website][i] = 0
            ip = pair['response']['ip']
            try:
                ips[ip].add(website)
            except KeyError:
                ips[ip] = set([website])
            for j, pkt in enumerate(pcap_data):
                pkt_timestamp = pkt['timestamp']
                if not req_timestamp <= pkt_timestamp < req_timestamp + tolerance:
                    continue
                if pkt['dst'] == ip:
                    pcap_data[j]['website'] = [website]
                    statistics[website][i] += 1
    summarized_stats = {}
    for website in statistics:
        summarized_stats[website] = {}
        for key in statistics[website]:
            try:
                summarized_stats[website][statistics[website][key]] += 1
            except KeyError:
                summarized_stats[website][statistics[website][key]] = 1
    print summarized_stats
    return pcap_data


def res_pkt_stats(json_data, pcap_data, time_from, time_to):
    """Response-packet matching"""
    tolerance = 0.01  # in seconds
    statistics = {}
    for website in json_data:
        statistics[website] = {}
        for i, pair in enumerate(json_data[website]):
            res_timestamp = pair['response']['timeStamp'] / 1000.
            if not time_from.get_seconds() < res_timestamp < time_to.get_seconds():
                continue
            statistics[website][i] = 0
            ip = pair['response']['ip']
            try:
                ips[ip].add(website)
            except KeyError:
                ips[ip] = set([website])
            for j, pkt in enumerate(pcap_data):
                pkt_timestamp = pkt['timestamp']
                if not res_timestamp - tolerance < pkt_timestamp <= res_timestamp:
                    continue
                if pkt['src'] == ip:
                    try:
                        pcap_data[j]['website'].append(website)
                    except KeyError:
                        pcap_data[j]['website'] = [website]
                    statistics[website][i] += 1
    summarized_stats = {}
    for website in statistics:
        summarized_stats[website] = {}
        for key in statistics[website]:
            try:
                summarized_stats[website][statistics[website][key]] += 1
            except KeyError:
                summarized_stats[website][statistics[website][key]] = 1
    print summarized_stats
    return pcap_data


def assign_by_ip(pcap_data):
    for i, pkt in enumerate(pcap_data):
        if 'website' in pkt:
            continue
        if pkt['src'] in ips:
            website = ips[pkt['src']]
        elif pkt['dst'] in ips:
            website = ips[pkt['dst']]
        else:
            website = None
        pcap_data[i]['website'] = website
    return pcap_data


def assign_by_time_tab(pcap_data, timing_data):
    print timing_data
    for i, pkt in enumerate(pcap_data):
        if 'website' in pkt:
            continue
        else:
            for j in range(1, len(timing_data)):
                if timing_data[j-1]['timeStamp'] / 1000. < pkt['timestamp'] < timing_data[j]['timeStamp'] / 1000.:
                    pcap_data[i]['website'] = timing_data[j-1]['website']
                    break
            pcap_data[i]['website'] = timing_data[j]['website']
    return pcap_data


def main(json_name, pcap_name, preprocessed):
    """Main method"""
    json_file = open(json_name)
    pcap_file = open(pcap_name)
    if preprocessed:
        json_data = json.load(json_file)
        pair_data = json_data['pairs']
        timing_data = json_data['timing']
    else:
        raw_json_data = json.load(json_file)
        pair_data = preprocess_json(raw_json_data)
        timing_data = preprocess_time_tab_data(raw_json_data)
    pcap_data = savefile.load_savefile(pcap_file, verbose=True)
    timestamp_json_from, timestamp_json_to = get_json_time_limits(pair_data)
    timestamp_pcap_from, timestamp_pcap_to = get_pcap_time_limits(pcap_data.packets)
    timestamp_abs_from, timestamp_abs_to = get_abs_time_limits(timestamp_json_from, timestamp_json_to,
                                                               TimeStamp(timestamp_pcap_from),
                                                               TimeStamp(timestamp_pcap_to))
    parsed_pcap = parse_pcap(pcap_data.packets, timestamp_abs_from, timestamp_abs_to)
    parsed_pcap = req_pkt_stats(pair_data, parsed_pcap, timestamp_abs_from, timestamp_abs_to)
    parsed_pcap = res_pkt_stats(pair_data, parsed_pcap, timestamp_abs_from, timestamp_abs_to)
    parsed_pcap = assign_by_ip(parsed_pcap)
    parsed_pcap = assign_by_time_tab(parsed_pcap, timing_data)

    csv_file = open('req-res.csv', 'w')
    field_names = ['timestamp', 'v', 'hl', 'tos', 'len', 'id', 'flags', 'off', 'ttl', 'p', 'sum', 'src', 'dst', 'opt', 'pad', 'website']
    writer = csv.DictWriter(csv_file, fieldnames=field_names)
    writer.writeheader()
    for pkt_obj in parsed_pcap:
        writer.writerow(pkt_obj)
    csv_file.close()
    # for i in xrange(100):
    #     print i
    # res_pkt_stats(json_data, pcap_data.packets, timestamp_abs_from, timestamp_abs_to, 10/1000.)
    print timestamp_abs_from.get_ms(), timestamp_abs_to.get_ms()
    print timestamp_abs_from.get_datetime(), timestamp_abs_to.get_datetime()


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