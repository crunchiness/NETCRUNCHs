#!/usr/bin/env python
__author__ = 'Ingvaras Merkys'

import unittest
from json_analyser import preprocess_time_tab_data


class TestJsonAnalyserMethods(unittest.TestCase):
    expected = [
        {
            'timeStamp': 1,
            'website': 'agurkai'
        },
        {
            'timeStamp': 5,
            'website': 'burokai'
        },
        {
            'timeStamp': 13,
            'website': 'morkos'
        },
        {
            'timeStamp': 25,
            'website': 'pomidorai'
        },
        {
            'timeStamp': 30,
            'website': 'morkos'
        }
    ]
    json_data = {
        'activeTab': [
            {
                'timeStamp': 1,
                'id': 20
            },
            {
                'timeStamp': 13,
                'id': 63
            },
            {
                'timeStamp': 25,
                'id': 30
            }
        ],
        'tabChanges': {
            '20': [
                {
                    'timeStamp': 1,
                    'website': 'agurkai'
                },
                {
                    'timeStamp': 5,
                    'website': 'burokai'
                }
            ],
            '63': [
                {
                    'timeStamp': 6,
                    'website': 'morkos'
                }
            ],
            '30': [
                {
                    'timeStamp': 25,
                    'website': 'pomidorai'
                },
                {
                    'timeStamp': 30,
                    'website': 'morkos'
                }
            ]
        }
    }

    def test_preprocess_time_tab_data(self):
        self.assertEqual(preprocess_time_tab_data(self.json_data), self.expected)


if __name__ == '__main__':
    unittest.main()