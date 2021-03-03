#!/usr/bin/python3
import sys
from argparse import *
from lib import settings

class wipenOptionClass():

    def __init__(self, options):
        self.options = options

    @classmethod
    def setOptions(self):
        parser = ArgumentParser(prog=sys.argv[0],
            description='',
            usage='',
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

        # Basic error handling of the programs initalisation
        try:
            arg_test = sys.argv[1]
        except IndexError:
            parser.print_help()
            return 1

        args, leftovers = parser.parse_known_args()
        options = args.__dict__
        print(self)
        return options
