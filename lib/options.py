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
            usage='sudo python3 /opt/wipen/wipen2.py -f [PCAP CAP] --ssid-pattern [P1] [P2] -s [TARGET SSID] -o [OUTFILE] |tee -a [OUTFILE].log',
            add_help=True
        )

        wipenGeneralOptions = parser.add_argument_group(
            title='General Settings'
        )

        wipenGeneralOptions.add_argument('-v', '--verbose',
            dest='verbose',
            action='store_true',
            default=False,
            help='Enable verbose'
        )

        wipenGeneralOptions.add_argument('--show-final',
            dest='show_final',
            action='store_true',
            default=False,
            help='Show final JSON payload'
        )

        wipenGeneralOptions.add_argument('-o', '--output',
            dest='output_filename',
            type=str,
            default=None,
            help='Specify output filename',
            required=True
        )

        wipenGeneralOptions.add_argument('--threshold',
            dest='periodic_file_update',
            type=int,
            default=settings.DEFAULT_PERIODIC_FILE_UPDATE_TIMER,
            help='Set periodic update for output file time in minutes (default: {})'.format(settings.DEFAULT_PERIODIC_FILE_UPDATE_TIMER)
        )

        sourceMode = parser.add_argument_group(title='Packet Source Settings', description='Specify source for targeting information')
        sourceMode.add_argument('-m', choices=[0,1], dest='mode', type=int, help='0 = live, 1 = pcap', required=True)

        wipenLiveOptions = parser.add_argument_group(
            title='Live Parsing Settings', description='Specify packet location when `-m 0` has been selected'
        )

        wipenLiveOptions.add_argument('-i', '--interface',
            dest='interface',
            type=str,
            help='Specify the wireless interface to use to capture packets',
        )

        wipenLiveOptions.add_argument('-r', '--rate',
            dest='hop_rate',
            type=int,
            default=1,
            help='Control how quickly interface will hop to next channel in seconds (Default: 1 second)',
        )

        wipenLiveOptions.add_argument('-T', '--timer',
            dest='capture_length',
            type=int,
            default=60*30,
            help='Specify how long to capture packets for as seconds (Default: 30 minutes)',
        )

        wipenLiveOptions.add_argument('--save-pcap',
            dest='save_pcap',
            action='store_true',
            help='Create pcap of captured packets instead of discarding packets',
        )

        wipenLiveOptions.add_argument('-O', '--output-pcap',
            dest='output_pcap',
            help='Specify name of pcap to store live captured packets',
        )

        wipenPcapOptions = parser.add_argument_group(
            title='PCAP Parsing Settings', description='Specify packet location when `-m 1` has been selected'
        )

        wipenPcapOptions.add_argument('-f', '--file',
            dest='pcap_filename',
            type=str,
            nargs='+',
            help='Provide one or more pcap to analysis',
        )

        processingOptions = parser.add_argument_group(title='Packet Processing Settings', description='Control the level of interrogation that is performed per packet')

        processingOptions.add_argument('--skip-similar-bssid',
            dest='skip_similar_bssid',
            action='store_true',
            default=False,
            help='Skip searching for similar BSSID'
        )

        processingOptions.add_argument('--skip-similar-ssid',
            dest='skip_similar_ssid',
            action='store_true',
            default=False,
            help='Skip searching for similar SSID'
        )

        processingOptions.add_argument('-s', '--ssid',
            dest='target_ssid',
            nargs='+',
            help='Specify a one ore more SSID to analysis',
            required=True
        )

        processingOptions.add_argument('--ssid-pattern',
            dest='ssid_pattern',
            nargs='+',
            help='Provide one or more possible SSID patterns to search for.'
        )

        processingOptions.add_argument('-I', '--ignore-bssid',
            dest='ignore_bssid',
            nargs='+',
            default=settings.DEFAULT_IGNORED_BSSID,
            help='Specify one or more BSSID to ignore during the parsing (default: {})'.format(settings.DEFAULT_IGNORED_BSSID)
            )

        processingOptions.add_argument('--ignore-client',
            dest='ignore_client',
            nargs='+',
            default=settings.DEFAULT_IGNORED_STA,
            help='Specify one or more STA addresses to ignore during parsing (default: {})'.format(settings.DEFAULT_IGNORED_STA))

        processingOptions.add_argument('--depth',
            dest='depth',
            type=int,
            default=settings.BSSID_INSPECTION_DEPTH,
            help='Depth to match the number of fields of a BSSID address (default: {})'.format(settings.BSSID_INSPECTION_DEPTH)
        )

        processingOptions.add_argument('--disable-vendor-mac-refresh',
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

        if( args.mode == 0 and not args.interface):
            parser.error('when -m 0 is selected, you must include the -i argument')
        if( args.mode == 1 and not args.pcap_filename) :
            parser.error('when -m 1 is selected, you must include the -f argument')
        if( args.mode == 0 and args.save_pcap and not args.output_pcap):
            args.output_pcap = '{}.pcap'.format(args.output_filename.split('.')[0])

        return args.__dict__
