#!/usr/bin/python3
import sys
from argparse import *
from lib import settings

class wipenOptionClass():

    @classmethod
    def __init__(self, options):
        self.options = options

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
            nargs='+',
            help='Provide one or more pcap to analysis',
            required=True
        )

        wipenGeneralOptions.add_argument('-o', '--output',
            dest='output_filename',
            type=str,
            default=None,
            help='Specify output filename',
            required=True
        )

        wipenGeneralOptions.add_argument('-v', '--verbose',
            dest='verbose',
            action='store_true',
            default=False,
            help='Enable verbose'
        )

        wipenGeneralOptions.add_argument('--skip-similar-bssid',
            dest='skip_similar_bssid',
            action='store_true',
            default=False,
            help='Skip searching for similar BSSID'
        )

        wipenGeneralOptions.add_argument('--skip-similar-ssid',
            dest='skip_similar_ssid',
            action='store_true',
            default=False,
            help='Skip searching for similar SSID'
        )

        wipenGeneralOptions.add_argument('--show-final',
            dest='show_final',
            action='store_true',
            default=False,
            help='Show final JSON payload'
        )

        wipenGeneralOptions.add_argument('--threshold',
            dest='periodic_file_update',
            type=int,
            default=settings.DEFAULT_PERIODIC_FILE_UPDATE_TIMER,
            help='Set periodic update for output file time in minutes (default: {})'.format(settings.DEFAULT_PERIODIC_FILE_UPDATE_TIMER)
        )

        wipenParserOptions.add_argument('-s', '--ssid',
            dest='target_ssid',
            nargs='+',
            help='Specify a one ore more SSID to analysis',
            required=True
        )

        wipenParserOptions.add_argument('--ssid-pattern',
            dest='ssid_pattern',
            nargs='+',
            help='Provide one or more possible SSID patterns to search for.'
        )

        wipenParserOptions.add_argument('-I', '--ignore-bssid',
            dest='ignore_bssid',
            nargs='+',
            default=settings.DEFAULT_IGNORED_BSSID,
            help='Specify one or more BSSID to ignore during the parsing (default: {})'.format(settings.DEFAULT_IGNORED_BSSID)
            )

        wipenParserOptions.add_argument('--ignore-client',
            dest='ignore_client',
            nargs='+',
            default=settings.DEFAULT_IGNORED_STA,
            help='Specify one or more STA addresses to ignore during parsing (default: {})'.format(settings.DEFAULT_IGNORED_STA))

        wipenParserOptions.add_argument('--depth',
            dest='depth',
            type=int,
            default=settings.BSSID_INSPECTION_DEPTH,
            help='Depth to match the number of fields of a BSSID address (default: {})'.format(settings.BSSID_INSPECTION_DEPTH)
        )

        wipenParserOptions.add_argument('--disable-vendor-mac-refresh',
            dest='disable_vendor_mac_refresh',
            action='store_true',
            default=False,
            help='Disable refresh of vendor MAC table refresh (default: False)')

        # Basic error handling of the programs initalisation
        try:
            arg_test = sys.argv[1]
        except IndexError:
            parser.print_help()
            sys.exit(1)

        args, leftovers = parser.parse_known_args()
        return args.__dict__
