#!/usr/bin/env python
__author__ = 'Ingvaras Merkys'

import json
import time
import argparse
from timestamp import TimeStamp


def write_stats(stats):
    stats_file = open('stats.log', 'a')
    stats_file.write('='*100 + '\n')
    stats_file.write('json_analyser.py\n')
    stats_file.write(time.strftime("%c") + '\n')
    stats_file.write('='*100 + '\n')
    stats_file.write('Web app\t# of pairs\n')
    for key in stats['websites']:
        stats_file.write(key + '\t' + str(stats['websites'][key]) + '\n')
    stats_file.write('='*100 + '\n')
    stats_file.write('# of pairs (incl. empty): {0}\n'.format(stats['total']))
    stats_file.write('# of empty pairs: {0}\n'.format(stats['no_data']))
    stats_file.write('# of pairs with request only: {0}\n'.format(stats['request_only']))
    stats_file.write('# of pairs with response only: {0}\n'.format(stats['response_only']))
    stats_file.write('# of responses from disk cache: {0}\n'.format(stats['from_cache']))
    stats_file.write('Response from cache: {0:.1f}%\n'.format(stats['from_cache'] * 100 / float(stats['total'])))
    stats_file.close()


def preprocess_json(data):
    """Filter out cache responses, bad data, build statistics"""
    pairs = data['pairs']
    stats = {
        'websites': {},
        'from_cache': 0,
        'total': 0,
        'response_only': 0,
        'request_only': 0,
        'no_data': 0,
        'wtf': {}
    }
    filtered_data = {}
    for i, website in enumerate(pairs):
        stats['websites'][website] = 0
        for j, pair in enumerate(pairs[website]['pairs']):
            if pair is None:
                stats['no_data'] += 1
            # request and response are missing
            elif pair['response'] is None and pair['request'] is None:
                stats['no_data'] += 1
            # only response if missing
            elif pair['response'] is None:
                stats['request_only'] += 1
            # only request is missing
            elif pair['request'] is None:
                stats['response_only'] += 1
            # everything is ok
            else:
                # record and dismiss if from cache
                if pair['response']['fromCache']:
                    stats['from_cache'] += 1
                else:
                    # save good pair
                    try:
                        filtered_data[website].append(pair)
                    except KeyError:
                        filtered_data[website] = [pair]
            # count all pairs
            stats['websites'][website] += 1
            stats['total'] += 1
    write_stats(stats)
    return filtered_data


def preprocess_time_tab_data(json_data):
    """Transforms active tab data into more usable form"""
    active_tab = json_data['activeTab']
    tab_changes = json_data['tabChanges']
    opened_website = []
    for i in range(1, len(active_tab)+1):
        time_stamp_from = active_tab[i-1]['timeStamp']
        try:
            time_stamp_to = active_tab[i]['timeStamp']
        except IndexError:
            time_stamp_to = float('inf')
        tab_id = str(active_tab[i-1]['id'])
        website = None
        if tab_id not in tab_changes:
            continue
        for change in tab_changes[tab_id]:
            if change['timeStamp'] <= time_stamp_from:
                website = change['website']
            elif change['timeStamp'] < time_stamp_to:
                if change['website'] != website:
                    opened_website.append({
                        'timeStamp': time_stamp_from,
                        'website': website
                    })
                    time_stamp_from = change['timeStamp']
                    website = change['website']
            else:
                opened_website.append({
                    'timeStamp': time_stamp_from,
                    'website': website
                })
                break
        # if didn't break
        else:
            opened_website.append({
                'timeStamp': time_stamp_from,
                'website': website
            })
    return opened_website


def get_avg_delays(data):
    # calculates average delay between request and response
    delays = {}
    for website in data:
        diff_sum = 0
        num_pairs = 0
        for pair in data[website]:
            diff_sum += pair['response']['timeStamp'] - pair['request']['timeStamp']
            num_pairs += 1
        avg_delay = diff_sum / (1000.0 * num_pairs)
        delays[website] = avg_delay
    return delays


def get_json_time_limits(data):
    """"Gets accurate time limits of JSON data"""
    first_request_time = float('inf')
    last_response_time = 0
    for website in data:
        for pair in data[website]:
            if pair['request']['timeStamp'] < first_request_time:
                first_request_time = pair['request']['timeStamp']
            if pair['response']['timeStamp'] > last_response_time:
                last_response_time = pair['response']['timeStamp']
    return TimeStamp(first_request_time / 1000.0), TimeStamp(last_response_time / 1000.0)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='JSON analyser.')
    parser.add_argument('json_name', nargs='?', type=str, help='input JSON file (\'data.json\' by default)',
                        default='data.json')
    args = parser.parse_args()
    file_name = args.json_name
    input_file = open(file_name)
    data = json.load(input_file)

    # filter data
    filtered_pairs = preprocess_json(data)

    # preprocess active tab data
    prepared_time = preprocess_time_tab_data(data)

    # write preprocessed data into new file
    file_name_out = file_name[:-5] + '_preprocessed.json'
    output_file = open(file_name_out, 'w')
    json.dump({
        'pairs': filtered_pairs,
        'timing': prepared_time
    }, output_file)
    output_file.close()