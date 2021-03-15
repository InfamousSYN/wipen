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
    def setOptions(self):
        parser = ArgumentParser(prog=sys.argv[0],
            description='automated wireless pcap dissector',
            usage='python3 wipen.py -f example.pcap -s example',
            add_help=True
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

        wipenParserOptions.add_argument('--depth',
            dest='depth',
            type=int,
            default=settings.BSSID_INSPECTION_DEPTH,
            help='Depth to match the number of fields of a BSSID address (default: {})'.format(settings.BSSID_INSPECTION_DEPTH)
        )

        # Basic error handling of the programs initalisation
        try:
            arg_test = sys.argv[1]
        except IndexError:
            parser.print_help()
            sys.exit(1)

        args, leftovers = parser.parse_known_args()
        options = args.__dict__

        for key, value in options.items():
            setattr(self, key, value)

        wipenOptionClass.checkSSIDandSSIDLIST(parser)

        return options
