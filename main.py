#!/usr/bin/env python
__author__ = 'Ingvaras Merkys'

import json
import csv
import argparse
from pcapfile import savefile
from json_analyser import get_json_time_limits, preprocess_json, preprocess_time_tab_data
from pcap_analyser import get_pcap_time_limits, parse_pcap
from timestamp import TimeStamp
from pcap_analyser import FIELD_NAMES
# IP dictionary
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
                ips[ip] = {website}
            for j, pkt in enumerate(pcap_data):
                pkt_timestamp = pkt['timestamp']
                if not req_timestamp <= pkt_timestamp < req_timestamp + tolerance:
                    continue
                if pkt['dst'] == ip:
                    pcap_data[j]['source'].add('REQ')
                    pcap_data[j]['website'].add(website)
                    pcap_data[j]['url'] = pair['request']['url']
                    statistics[website][i] += 1
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
                ips[ip] = {website}
            for j, pkt in enumerate(pcap_data):
                pkt_timestamp = pkt['timestamp']
                if not res_timestamp - tolerance < pkt_timestamp <= res_timestamp:
                    continue
                if pkt['src'] == ip:
                    pcap_data[j]['source'].add('RES')
                    pcap_data[j]['website'].add(website)
                    statistics[website][i] += 1
    return pcap_data


def assign_by_flow(pcap_data):
    """
    Assigns website based on stream ID. Adds to the set, also adds 'FLOW' as source
    :param pcap_data:
    :return:
    """
    # collect possible websites for stream id
    websites = {
        # stream_id: {website: count}
    }
    for i, pkt in enumerate(pcap_data):
        if pkt['protocol'] == 'TCP' and pkt['src_port'] != -1 and pkt['dst_port'] != -1:
            stream_id = pkt['src'] + str(pkt['src_port']) + pkt['dst'] + str(pkt['dst_port'])

            # get website in string form, skip if empty
            try:
                website = next(iter(pkt['website']))
            except StopIteration:
                continue

            # increment website count in this stream_id
            try:
                websites[stream_id][website] += 1
            except KeyError:
                websites[stream_id] = {website: 1}

    # select the most likely website for steam id
    for stream_id in websites.keys():
        max_value = 0
        top_website = ''
        for key, value in websites[stream_id].iteritems():
            if value > max_value:
                max_value = value
                top_website = key
        websites[stream_id] = top_website

    # add website by stream id to pcap_data
    for i, pkt in enumerate(pcap_data):
        if pkt['protocol'] == 'TCP' and pkt['src_port'] != -1 and pkt['dst_port'] != -1:
            stream_id = pkt['src'] + str(pkt['src_port']) + pkt['dst'] + str(pkt['dst_port'])
            try:
                flow_site = websites[stream_id]
                pcap_data[i]['source'].add('FLOW')
                pcap_data[i]['website'].add(flow_site)
            except KeyError:
                continue

    return pcap_data


def assign_by_ip(pcap_data):
    for i, pkt in enumerate(pcap_data):
        if len(pkt['website']) > 0:
            continue
        if pkt['src'] in ips:
            pcap_data[i]['source'].add('IP')
            pcap_data[i]['website'] = ips[pkt['src']]
        elif pkt['dst'] in ips:
            pcap_data[i]['source'].add('IP')
            pcap_data[i]['website'] = ips[pkt['dst']]
    return pcap_data


def assign_by_time_tab(pcap_data, timing_data):
    for i, pkt in enumerate(pcap_data):
        if not (('RES' in pcap_data[i]['source']) or ('REQ' in pcap_data[i]['source']) or ('FLOW' in pcap_data[i]['source'])):
            for j in range(1, len(timing_data) + 1):
                time_from = timing_data[j - 1]['timeStamp'] / 1000.
                try:
                    time_to = timing_data[j]['timeStamp'] / 1000.
                except IndexError:
                    time_to = float('inf')
                if time_from < pkt['timestamp'] < time_to:
                    if timing_data[j - 1]['website'] in pkt['website']:
                        pcap_data[i]['source'].add('TIME')
                        pcap_data[i]['website'] = {timing_data[j - 1]['website']}
                    else:
                        pcap_data[i]['source'].add('TIME')
                        pcap_data[i]['website'].add(timing_data[j - 1]['website'])
                    break
    return pcap_data


def stringify(pcap_data):
    for i, pkt in enumerate(pcap_data):
        if len(pkt['website']) == 0:
            pcap_data[i]['website'] = 'Other'
        else:
            pcap_data[i]['website'] = ';'.join(sorted(list(pkt['website'])))
        pcap_data[i]['source'] = ';'.join(sorted(list(pkt['source'])))
    return pcap_data


def main(json_name, pcap_name, preprocessed, output_file):
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
    # packet matching using request data
    parsed_pcap = req_pkt_stats(pair_data, parsed_pcap, timestamp_abs_from, timestamp_abs_to)
    # packet matching using response data
    parsed_pcap = res_pkt_stats(pair_data, parsed_pcap, timestamp_abs_from, timestamp_abs_to)
    # packet matching by tcp flow
    parsed_pcap = assign_by_flow(parsed_pcap)
    # packet matching by ip
    parsed_pcap = assign_by_ip(parsed_pcap)
    # packet matching by active tab time data
    parsed_pcap = assign_by_time_tab(parsed_pcap, timing_data)

    parsed_pcap = stringify(parsed_pcap)

    # write output to CSV file
    csv_file = open(output_file, 'w')
    writer = csv.DictWriter(csv_file, fieldnames=FIELD_NAMES)
    writer.writeheader()
    for pkt_obj in parsed_pcap:
        writer.writerow(pkt_obj)
    csv_file.close()
    print 'ALL DONE'


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='NETCRUNCHs main module.')
    parser.add_argument('-p', '--preprocessed', help='use preprocessed JSON',
                        action='store_true')
    parser.add_argument('json_name', nargs='?', type=str,
                        help='input JSON file (\'data.json\' or \'data_preprocessed.json\' by default)')
    parser.add_argument('pcap_name', nargs='?', type=str, help='input PCAP file (default \'dump.pcap\')',
                        default='dump.pcap')
    parser.add_argument('output', nargs='?', type=str, help='output file (default \'out.csv\')', default='out.csv')

    args = parser.parse_args()

    if args.json_name is None:
        if args.preprocessed:
            args.json_name = 'data_preprocessed.json'
        else:
            args.json_name = 'data.json'

    main(args.json_name, args.pcap_name, args.preprocessed, args.output)
