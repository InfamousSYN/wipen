#!/usr/bin/python3

def loadOptions():
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog=sys.argv[0],
        description='automated tool for hopping between wireless channels based collected target information.',
        usage='python3 wipenHopper.py -f example.json -s example',
        add_help=True
    )

    GeneralOptions = parser.add_argument_group(
        title='General Settings'
    )

    TargetOptions = parser.add_argument_group(
        title='Target Settings'
    )

    GeneralOptions.add_argument('-f', '--file',
        dest='json_filename',
        type=str,
        help='Specify wipen JSON file to read',
        required=True
    )

    GeneralOptions.add_argument('-i', '--interface',
        dest='interface',
        type=str,
        help='Specify interface to monitor on',
        required=True
    )

    GeneralOptions.add_argument('-S', '--speed',
        dest='hop_speed',
        type=int,
        default=1,
        help='Control how quickly interface will hop between channels',
    )

    # Basic error handling of the programs initalisation
    try:
        arg_test = sys.argv[1]
    except IndexError:
        parser.print_help()
        sys.exit(1)

    args, leftovers = parser.parse_known_args()
    return args.__dict__

def deep_search(filename=None, target_key=None, payload=None):
    import json
    with open(filename, 'r') as f:
        payload = f.read()
        f.close()

    results = []

    def _decode_dict(a_dict):
        try:
            results.append(a_dict[target_key])
        except KeyError:
            pass
        return a_dict
    json.loads(payload, object_hook=_decode_dict)
    return set(results)

if __name__ == '__main__':
    import subprocess
    import time

    _version = '1.0.0'

    print('[+] Launching wipenHopper {}'.format(_version))
    options = loadOptions()
    print('[-] Extracting list of channels to target from file: {}'.format(options['json_filename']))
    channels = deep_search(filename=options['json_filename'], target_key='frequency')
    print('[-] Channels being targeted: {}'.format(channels))

    print('[-] Setting \'{}\' not to be managed by network manager'.format(options['interface']))
    try:
        subprocess.run(['nmcli', 'device', 'set', '{}'.format(options['interface']), 'managed', 'no'])
    except Exception as e:
        print('[!] Error caught when attempting to demanage network manager')
        print('[!] {}'.format(e))
        exit(1)

    print('[-] Placing \'{}\' into monitor mode'.format(options['interface']))
    try:
        subprocess.run(['iwconfig', '{}'.format(options['interface']), 'mode', 'Monitor'])
    except Exception as e:
        print('[!] Error caught when attempting to place interface into monitor mode')
        print('[!] {}'.format(e))
        exit(1)

    try:
        print('[-] Looping through extracted channels')
        while True:
            for channel in channels:
                if(len(str(channel)) >= 4):
                    pass
                else:
                    subprocess.run(['iwconfig', '{}'.format(options['interface']), 'channel', '{}'.format(channel)])
                    time.sleep(options['hop_speed'])

    except KeyboardInterrupt:
        print('[-] Resetting interface back to managed mode')
        subprocess.run(['iwconfig', '{}'.format(options['interface']), 'mode', 'Managed'])

        print('[-] Configuring network manager to re-manage interface')
        subprocess.run(['nmcli', 'device', 'set', '{}'.format(options['interface']), 'managed', 'yes'])
        exit(0)
