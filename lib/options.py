#!/usr/bin/python3
import sys
from argparse import *
from lib import settings

class wipenOptionClass():

    def __init__(self, options):
        self.options = options

    @classmethod
    def checkSSIDandSSIDLIST(self, parser):
        if(self.target_ssid is not None and self.target_ssid_list is not None):
            parser.error('[!] Specify only -s or -S')
        return 0

    @classmethod
    def checkBSSIDandBSSIDLIST(self, parser):
        if(self.target_bssid is not None and self.target_bssid_list is not None):
            parser.error('[!] Specify only -b or -B')
        return 0

    @classmethod
    def setOptions(self):
        parser = ArgumentParser(prog=sys.argv[0],
            description='',
            usage='',
            add_help=False
        )

        wipenGeneralOptions = parser.add_argument_group(
            title='General Settings'
        )

        wipenParserOptions = parser.add_argument_group(
            title='PCAP Parsing Settings'
        )

        wipenGeneralOptions.add_argument('-f', '--file',
            dest='pcap_filename',
            type=str,
            default=None,
            help='Specify target pcap to analysis'
        )

        wipenParserOptions.add_argument('-s', '--ssid',
            dest='target_ssid',
            type=str,
            default=None,
            help='Specify a single SSID to analysis'
        )

        wipenParserOptions.add_argument('-S', '--ssid-list',
            dest='target_ssid_list',
            type=str,
            default=None,
            help='Specify a single SSID to analysis'
        )

        wipenParserOptions.add_argument('-b', '--bssid',
            dest='target_bssid',
            type=str,
            default=None,
            help='Specify a single BSSID to analysis'
        )

        wipenParserOptions.add_argument('-B', '--bssid-list',
            dest='target_bssid_list',
            type=str,
            default=None,
            help='Specify a single BSSID to analysis'
        )

        wipenParserOptions.add_argument('--depth',
            dest='depth',
            type=int,
            default=3,
            help='Depth to match the number of fields of a BSSID address (default: 3)'
        )

        wipenParserOptions.add_argument('-c', '--client',
            dest='target_client',
            type=str,
            default=None,
            help='Specify a single client (STA) to analysis'
        )

        wipenParserOptions.add_argument('-C', '--client-list',
            dest='target_client_list',
            type=str,
            default=None,
            help='Specify a list of clients (STA) to analysis'
        )

        # Basic error handling of the programs initalisation
        try:
            arg_test = sys.argv[1]
        except IndexError:
            parser.print_help()
            return 1

        args, leftovers = parser.parse_known_args()
        options = args.__dict__

        for key, value in options.items():
            setattr(self, key, value)

        wipenOptionClass.checkSSIDandSSIDLIST(parser)
        wipenOptionClass.checkBSSIDandBSSIDLIST(parser)

        return options
