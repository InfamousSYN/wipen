# Overview

## pcap_merger

`pcap_merger` can be used to target specific pcaps and merge them into a single file.

```
sudo python3 wipen/tools/pcap_merger.py -f pcaps/1.pcap pcaps/2.pcap -o output.pcap
```

`pcap_merger` wildcard can be used to target pcaps indiscriminately.

```
sudo python3 wipen/tools/pcap_merger.py -f pcaps/*.pcap -o output.pcap
```

## wipenHopper

`wipenHopper` allows the user to extract the list of observed channels from the JSON output of [`wipen`](https://github.com/InfamousSYN/wipen) to automatically place an interface into monitor mode and hop between the desired interfaces for a more focused network capture of the targeted entity.

```
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~]
└─$ sudo python3 /opt/wipen/tools/wipenHopper.py -f acme.json -i wlan0
[+] Launching wipenHopper 1.0.0
[-] Extracting list of channels to target from file: acme.json
[-] Channels being targeted: {1, 3, 132, 5, 6, 7, 4, 9, 2437, 11, 13, 149, 157, 36, 44, 48, 52, 60, 64, 100, 108}
[-] Setting 'wlan0' not to be managed by network manager
[-] Placing 'wlan0' into monitor mode
[-] Looping through extracted channels
^C[-] Resetting interface back to managed mode
[-] Configuring network manager to re-manage interface
                                                                                                                    
┌──(vagrant㉿vagrant-kali-rolling-amd64)-[~]
└─$
```
