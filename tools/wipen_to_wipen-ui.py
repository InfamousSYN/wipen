#!/usr/bin/python3
import json
import uuid

#data = '{"target_ssid":{"bssid":[{"bssid": "00:35:1a:b0:26:2f", "frequency": 64, "protocol": "802.11ac", "authentication": "WPA2/802.1X", "associated_clients": [{"client_addr": "60:57:18:ff:5a:e1", "identities": [{"id": 0, "identity": "akayanc"}], "probes": [{"id": 0, "probe": ""}, {"id": 1, "probe": "target_ssid6"}, {"id": 2, "probe": "target_ssid7"}, {"id": 3, "probe": "target_ssid8"}, {"id": 4, "probe": "target_ssid9"}], "vendor": "Intel Corporate"},{"client_addr": "60:57:18:12:5a:23", "identities": [], "probes": [{"id": 0, "probe": ""}, {"id": 1, "probe": "target_ssid6"}, {"id": 2, "probe": "target_ssid7"}, {"id": 3, "probe": "target_ssid8"}, {"id": 4, "probe": "target_ssid9"}], "vendor": "Intel Corporate"}],"similar_bssid": [{"ssid": "target_ssid2", "bssid": "00:35:1a:b0:26:2e", "protocol": "802.11ac", "frequency": 64, "authentication": "WPA2/802.1X", "hidden_ssid": false, "vendor": "Cisco Systems, Inc", "pmkid": [], "vendor": "Cisco Systems, Inc", "wps": "wps", "times_seen": 50},{"ssid": "target_ssid3", "bssid": "00:35:1a:b0:72:2f", "protocol": "802.11ac", "frequency": 64, "authentication": "WPA2/PSK", "hidden_ssid": false, "vendor": "Cisco Systems, Inc", "pmkid": [], "vendor": "Cisco Systems, Inc", "wps": "wps", "times_seen": 50}], "pmkid": [], "vendor": "Cisco Systems, Inc", "wps": "wps", "times_seen": 50},{"bssid": "00:35:1a:b0:26:6a", "frequency": 64, "protocol": "802.11ac", "authentication": "WPA2/802.1X", "associated_clients": [],"similar_bssid": [], "pmkid": [], "vendor": "Cisco Systems, Inc", "wps": "wps", "times_seen": 50}],"similar_ssid": [{"target_ssid2": {"bssid": [{"bssid": "00:35:1a:b0:26:2e", "frequency": 64, "protocol": "802.11ac", "authentication": "WPA2/802.1X", "associated_clients": [{"client_addr": "00:11:22:33:44:00", "identities": [], "probes": [{"id": 0, "probe": "target_ssid3"}, {"id": 1, "probe": "target_ssid5"}], "vendor": "CIMSYS Inc"}, {"client_addr": "40:ec:99:b2:70:96", "identities": [], "probes": [{"id": 0, "probe": ""}, {"id": 1, "probe": "target_ssid2"}], "vendor": "Intel Corporate"}, {"client_addr": "00:c0:ca:aa:af:2e", "identities": [{"id": 0, "identity": "obrienh"}], "probes": [], "vendor": "ALFA, INC."}, {"client_addr": "f6:8f:15:57:d3:cb", "identities": [{"id": 0, "identity": "akayanc"}], "probes": [{"id": 0, "probe": "target_ssid2"}], "vendor": null}], "similar_bssid": [], "pmkid": [], "vendor": "Cisco Systems, Inc", "wps": "wps", "times_seen": 8277, "hidden_ssid": false}], "similar_ssid": []}},{"target_ssid3": {"bssid": [{"bssid": "00:11:22:33:44:00", "frequency": 36, "protocol": "802.11ac", "authentication": "WPA2/802.1X", "associated_clients": [], "similar_bssid": [], "pmkid": [], "vendor": "CIMSYS Inc", "wps": "wps", "times_seen": 864, "hidden_ssid": false}, {"bssid": "00:35:1a:b0:72:2f", "frequency": 60, "protocol": "802.11ac", "authentication": "WPA2/802.1X", "associated_clients": [], "similar_bssid": [], "pmkid": [], "vendor": "Ruckus Wireless", "wps": "wps", "times_seen": 289, "hidden_ssid": false}], "similar_ssid": []}},{"target_ssid4": {"bssid": [{"bssid": "08:36:c9:02:1f:69", "frequency": 1, "protocol": "802.11b", "authentication": "WPA2/PSK", "associated_clients": [], "similar_bssid": [], "pmkid": [], "vendor": "NETGEAR", "wps": "wps", "times_seen": 1, "hidden_ssid": false}], "similar_ssid": []}}]}}'
#data = '{"ESA-Staff": {"bssid": [{"bssid": "74:ac:b9:c4:ec:d3", "frequency": 7, "protocol": "802.11b", "authentication": "WPA2/PSK", "associated_clients": [], "similar_bssid": [{"ssid": "ESA-Staff", "bssid": "74:ac:b9:c4:ec:94", "protocol": "802.11b", "frequency": 9, "authentication": "WPA2/PSK", "vendor": "Ubiquiti Inc", "times_seen": 1, "hidden_ssid": false}], "pmkid": [], "vendor": "Ubiquiti Inc", "wps": "wps", "times_seen": 1465, "hidden_ssid": false}, {"bssid": "74:ac:b9:c4:ec:94", "frequency": 9, "protocol": "802.11b", "authentication": "WPA2/PSK", "associated_clients": [{"client_addr": "8e:74:e4:7c:4f:ad", "identities": [], "probes": [{"id": 0, "probe": ""}], "vendor": null}, {"client_addr": "33:33:00:00:00:16", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:5e:7f:ff:fa", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:80:c2:00:00:0e", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:5e:00:00:fb", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:fb", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:01:00:03", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:5e:00:00:fc", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:01:00:02", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:ff:37:6c:97", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:02", "identities": [], "probes": [], "vendor": null}], "similar_bssid": [{"ssid": "ESA-Staff", "bssid": "74:ac:b9:c4:ec:d3", "protocol": "802.11b", "frequency": 7, "authentication": "WPA2/PSK", "vendor": "Ubiquiti Inc", "times_seen": 1, "hidden_ssid": false}], "pmkid": [], "vendor": "Ubiquiti Inc", "wps": "wps", "times_seen": 1425, "hidden_ssid": false}, {"bssid": "7a:ac:b9:c5:ec:94", "frequency": 36, "protocol": "802.11ac", "authentication": "WPA2/PSK", "associated_clients": [{"client_addr": "8e:74:e4:7c:4f:ad", "identities": [], "probes": [{"id": 0, "probe": ""}], "vendor": null}, {"client_addr": "bc:d0:74:02:d0:cd", "identities": [], "probes": [], "vendor": "Apple, Inc."}, {"client_addr": "01:00:5e:00:00:fb", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:fb", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:5e:7f:ff:fa", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:16", "identities": [], "probes": [], "vendor": null}, {"client_addr": "4c:44:5b:49:c4:ab", "identities": [], "probes": [], "vendor": "Intel Corporate"}, {"client_addr": "01:00:5e:00:00:16", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:01:00:03", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:5e:00:00:fc", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:02", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:01:00:02", "identities": [], "probes": [], "vendor": null}, {"client_addr": "2c:33:58:0e:af:6a", "identities": [], "probes": [{"id": 0, "probe": ""}, {"id": 1, "probe": "ESA-Staff"}], "vendor": "Intel Corporate"}, {"client_addr": "01:80:c2:00:00:0e", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:01", "identities": [], "probes": [], "vendor": null}], "similar_bssid": [{"ssid": "ESA-Staff", "bssid": "7a:ac:b9:c5:ec:d3", "protocol": "802.11ac", "frequency": 36, "authentication": "WPA2/PSK", "vendor": null, "times_seen": 1, "hidden_ssid": false}], "pmkid": [], "vendor": null, "wps": "wps", "times_seen": 891, "hidden_ssid": false}, {"bssid": "7a:ac:b9:c5:ec:d3", "frequency": 36, "protocol": "802.11ac", "authentication": "WPA2/PSK", "associated_clients": [{"client_addr": "22:ef:a0:b9:b6:4f", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:5e:7f:ff:fa", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:5e:00:00:fb", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:fb", "identities": [], "probes": [], "vendor": null}, {"client_addr": "06:0a:04:e4:df:67", "identities": [], "probes": [], "vendor": null}, {"client_addr": "0a:41:d9:2a:44:9b", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:5e:00:00:16", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:80:c2:00:00:0e", "identities": [], "probes": [], "vendor": null}, {"client_addr": "d2:b2:15:6d:be:1b", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:16", "identities": [], "probes": [], "vendor": null}, {"client_addr": "10:a5:1d:9d:d0:00", "identities": [], "probes": [], "vendor": "Intel Corporate"}, {"client_addr": "2c:33:58:0e:af:6a", "identities": [], "probes": [{"id": 0, "probe": ""}, {"id": 1, "probe": "ESA-Staff"}], "vendor": "Intel Corporate"}, {"client_addr": "c4:03:a8:b2:97:51", "identities": [], "probes": [{"id": 0, "probe": "ESA-Staff"}], "vendor": "Intel Corporate"}, {"client_addr": "33:33:00:01:00:03", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:5e:00:00:fc", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:02", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:01:00:02", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:ff:37:6c:97", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:01", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:00:0c:cc:cc:cc", "identities": [], "probes": [], "vendor": null}], "similar_bssid": [{"ssid": "ESA-Staff", "bssid": "7a:ac:b9:c5:ec:94", "protocol": "802.11ac", "frequency": 36, "authentication": "WPA2/PSK", "vendor": null, "times_seen": 1, "hidden_ssid": false}], "pmkid": [], "vendor": null, "wps": "wps", "times_seen": 895, "hidden_ssid": false}], "similar_ssid": [{"ESA-Guest": {"bssid": [{"bssid": "7a:ac:b9:c4:ec:d3", "frequency": 7, "protocol": "802.11b", "authentication": "WPA2/PSK", "associated_clients": [{"client_addr": "01:80:c2:00:00:0e", "identities": [], "probes": [], "vendor": null}, {"client_addr": "52:f8:18:e2:8c:0d", "identities": [], "probes": [{"id": 0, "probe": "ESA-Guest"}], "vendor": null}], "similar_bssid": [], "pmkid": [], "vendor": null, "wps": "wps", "times_seen": 3018, "hidden_ssid": false}, {"bssid": "7a:ac:b9:c4:ec:94", "frequency": 13, "protocol": "802.11b", "authentication": "WPA2/PSK", "associated_clients": [{"client_addr": "01:00:5e:00:00:fb", "identities": [], "probes": [], "vendor": null}, {"client_addr": "33:33:00:00:00:fb", "identities": [], "probes": [], "vendor": null}, {"client_addr": "01:80:c2:00:00:0e", "identities": [], "probes": [], "vendor": null}], "similar_bssid": [], "pmkid": [], "vendor": null, "wps": "wps", "times_seen": 2866, "hidden_ssid": false}, {"bssid": "7e:ac:b9:c5:ec:94", "frequency": 36, "protocol": "802.11ac", "authentication": "WPA2/PSK", "associated_clients": [], "similar_bssid": [], "pmkid": [], "vendor": null, "wps": "wps", "times_seen": 1792, "hidden_ssid": false}, {"bssid": "7e:ac:b9:c5:ec:d3", "frequency": 36, "protocol": "802.11ac", "authentication": "WPA2/PSK", "associated_clients": [], "similar_bssid": [], "pmkid": [], "vendor": null, "wps": "wps", "times_seen": 1778, "hidden_ssid": false}], "similar_ssid": []}}]}}'
#payload = json.loads(data)
#

def deep_search(target_key=None, payload=None):
    import json
    payload=json.dumps(payload)
    results = []
    def _decode_dict(a_dict):
        try:
            results.append(a_dict[target_key])
        except KeyError:
            pass
        return a_dict
    json.loads(payload, object_hook=_decode_dict)
    return results


def populateNodes(data=None):
    import uuid
    data_set = {"nodes":[],"edges":[]}

    bssid_ssid='Broadcasting'
    sta_ssid='ProbingFor'
    ssid_ssid='SimilarSSID'
    sta_identity='ActingAs'
    identity_bssid_psk='ConnectedToViaPSK'
    identity_bssid_eap='ConnectedToViaEAP'
    bssid_bssid='SimilarBSSID'

    unknown_identity_count = 1

    # add the initial target ssid node
    for _ssid_pos, _ssid in enumerate(data):
        payload=data[_ssid]
        data_set["nodes"].append({"label":_ssid, "wipen_type":payload['metadata'].get('_type'), "uuid":payload['metadata'].get('_id')})

        for _similar_ssid_pos, _similar_ssid in enumerate(data[_ssid]['similar_ssid']):
            _similar_ssid=next(iter(_similar_ssid))
            payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]
            data_set["nodes"].append({"label":_similar_ssid, "wipen_type":payload['metadata'].get('_type'), "uuid":payload['metadata'].get('_id')})
            data_set["edges"].append({"label":ssid_ssid, "source":payload['metadata'].get('_id'), "destination":data[_ssid]['metadata'].get('_id')})

        for _bssid_pos, _bssid in enumerate(data[_ssid]['bssid']):
            payload = data[_ssid]['bssid'][_bssid_pos]
            data_set["nodes"].append({"label":payload.get('bssid'), "wipen_type":payload['metadata'].get('_type'), "uuid":payload['metadata'].get('_id'), 'frequency':payload.get('frequency'), 'protocol':payload.get('protocol'), 'authentication':payload.get('authentication'), 'pmkid':payload.get('pmkid'), 'vendor':payload.get('vendor'), 'wps':payload.get('wps'), 'times_seen':payload.get('times_seen')})
            data_set["edges"].append({"label":bssid_ssid, "source":payload['metadata'].get('_id'), "destination":data[_ssid]['metadata'].get('_id')})

        for _similar_ssid_pos, _similar_ssid in enumerate(data[_ssid]['similar_ssid']):
            _similar_ssid=next(iter(_similar_ssid))
            for _similar_ssid_bssid_pos, _similar_ssid_bssid in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid']):
                payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]
                data_set["nodes"].append({"label":payload.get('bssid'), "wipen_type":payload['metadata'].get('_type'), "uuid":payload['metadata'].get('_id'), 'frequency':payload.get('frequency'), 'protocol':payload.get('protocol'), 'authentication':payload.get('authentication'), 'pmkid':payload.get('pmkid'), 'vendor':payload.get('vendor'), 'wps':payload.get('wps'), 'times_seen':payload.get('times_seen')})
                data_set["edges"].append({"label":bssid_ssid, "source":payload['metadata'].get('_id'), "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['metadata'].get('_id')})

    # add the client
    for _ssid_pos, _ssid in enumerate(data):
        for _bssid_pos, _bssid in enumerate(data[_ssid]['bssid']):
            if('PSK'.lower() in data[_ssid]['bssid'][_bssid_pos].get('authentication').lower()
            ):
                for _client_pos, _client in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients']):

                    payload = data[_ssid]['bssid'][_client_pos]['associated_clients'][_client_pos]
                    if( (payload.get('client_addr') not in deep_search(
                        target_key='label',
                        payload=data_set['nodes']
                    ))):
                        data_set["nodes"].append({"label":payload.get("client_addr"), "vendor":payload.get("vendor"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})

                    target_key = {"label":payload.get("client_addr"), "wipen_type":"sta"}

                    if(any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                        _uuid = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                        _uuid = _uuid.get("uuid")
                    else:
                        _uuid = str(uuid.uuid4())
                        data_set["nodes"].append({"label":payload.get("client_addr"), "wipen_type":"identity", "uuid":_uuid})

                    data_set["edges"].append({"label":sta_identity, "source":payload['metadata'].get('_id'), "destination":_uuid})
                    data_set["edges"].append({"label":identity_bssid_psk, "source":_uuid, "destination":data[_ssid]['bssid'][_bssid_pos]['metadata'].get('_id')})

                    payload = data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]
                    target_key = {"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type')}
                    if(any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                        _uuid = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                        _uuid = _uuid.get("uuid")
                    else:
                        _uuid = str(uuid.uuid4())
                        data_set["nodes"].append({"label":payload.get("client_addr"), "wipen_type":"identity", "uuid":_uuid})

                    data_set["edges"].append({"label":sta_identity, "source":payload['metadata'].get('_id'), "destination":_uuid})
                    data_set["edges"].append({"label":identity_bssid_psk, "source":_uuid, "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')})

            ### here are lots of issues
            elif('802.1X'.lower() in data[_ssid]['bssid'][_bssid_pos].get('authentication').lower() ):
                for _client_pos, _client in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients']):

                    payload = data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]
                    target_key = {"label":payload.get("client_addr"), "wipen_type":"sta"}
                    if(not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                        data_set["nodes"].append({"label":payload.get("client_addr"), "vendor":payload.get("vendor"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})
                    else: pass

                    if(data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos].get('identities') is not None):
                        for _identity_pos, _identity in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['identities']):
                        
                            payload = data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['identities'][_identity_pos]
                            target_key = {"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type')}
                            if(not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                                data_set["nodes"].append({"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})

                            target_key = {"label":sta_identity, "source":data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":payload["metadata"].get("_id")}
                            if(not any(d for d in data_set["edges"] if sum(d.get(k) == v for k, v in target_key.items()) >= 3)):
                                data_set["edges"].append({"label":sta_identity, "source":data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":payload["metadata"].get("_id")})
                            else: pass

                            target_key = {"label":identity_bssid_eap, "source":payload["metadata"].get("_id"), "destination":data[_ssid]['bssid'][_bssid_pos]['metadata'].get('_id')}
                            if(not any(d for d in data_set["edges"] if sum(d.get(k) == v for k, v in target_key.items()) >= 3)):
                                data_set["edges"].append({"label":identity_bssid_eap, "source":payload["metadata"].get("_id"), "destination":data[_ssid]['bssid'][_bssid_pos]['metadata'].get('_id')})
                            else: pass


                    else:
                        # make a dummy identity when unknown
                        _uuid = str(uuid.uuid4())
                        data_set["nodes"].append({"label":"unknown_identity_{}".format(unknown_identity_count), "wipen_type":"identity", "uuid":_uuid})
                        unknown_identity_count += 1
                        data_set["edges"].append({"label":sta_identity, "source":data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":_uuid})
                        data_set["edges"].append({"label":identity_bssid_eap, "source":_uuid, "destination":data[_ssid]['bssid'][_bssid_pos]['metadata'].get('_id')})

            else: pass

        for _similar_ssid_pos, _similar_ssid in enumerate(data[_ssid]['similar_ssid']):
            _similar_ssid=next(iter(_similar_ssid))
            for _similar_ssid_bssid_pos, _similar_ssid_bssid in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid']):
                if('PSK'.lower() in data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos].get('authentication').lower()
                ):
                    for _client_pos, _client in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients']):

                        payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]
                        if( (data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos].get('client_addr') not in deep_search(
                            target_key='label',
                            payload=data_set['nodes']
                        )) ):
                            data_set["nodes"].append({"label":payload.get("client_addr"), "vendor":payload.get("vendor"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})

                        target_key = {"label":payload.get("client_addr"), "wipen_type":"identity"}
                        if(any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                            _uuid = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                            _uuid = _uuid.get("uuid")
                        else:
                            _uuid = str(uuid.uuid4())
                            data_set["nodes"].append({"label":payload.get("client_addr"), "wipen_type":"identity", "uuid":_uuid})

                        data_set["edges"].append({"label":sta_identity, "source":payload['metadata'].get('_id'), "destination":_uuid})
                        data_set["edges"].append({"label":identity_bssid_psk, "source":_uuid, "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')})


                ### here are lots of issues
                elif('802.1X'.lower() in data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos].get('authentication').lower() ):
                    for _client_pos, _client in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients']):
    
                        payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]
                        target_key = {"label":payload.get("client_addr"), "wipen_type":"sta"}
                        if(not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                            data_set["nodes"].append({"label":payload.get("client_addr"), "vendor":payload.get("vendor"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})
    
                        if( _client.get('identities') is not None ):
                            for _identity_pos, _identity in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['identities']):
                            
                                payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['identities'][_identity_pos]
                                target_key = {"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type')}
                                if(not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                                    data_set["nodes"].append({"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})
    
                                target_key = {"label":sta_identity, "source":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":payload["metadata"].get("_id")}
                                if(not any(d for d in data_set["edges"] if sum(d.get(k) == v for k, v in target_key.items()) >= 3)):
                                    data_set["edges"].append({"label":sta_identity, "source":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":payload["metadata"].get("_id")})
                                else: pass
    
                                target_key = {"label":identity_bssid_eap, "source":payload["metadata"].get("_id"), "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')}
                                if(not any(d for d in data_set["edges"] if sum(d.get(k) == v for k, v in target_key.items()) >= 3)):
                                    data_set["edges"].append({"label":identity_bssid_eap, "source":payload["metadata"].get("_id"), "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')})
                                else: pass
    
    
                        else:
                            # make a dummy identity when unknown
                            _uuid = str(uuid.uuid4())
                            data_set["nodes"].append({"label":"unknown_identity_{}".format(unknown_identity_count), "wipen_type":"identity", "uuid":_uuid})
                            unknown_identity_count += 1
                            data_set["edges"].append({"label":sta_identity, "source":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":_uuid})
                            data_set["edges"].append({"label":identity_bssid_eap, "source":_uuid, "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')})


    # add the probe
    for _ssid_pos, _ssid in enumerate(data):
        for _bssid_pos, _bssid in enumerate(data[_ssid]['bssid']):
            for _client_pos, _client in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients']):
                for _probe_pos, _probe in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['probes']):

                    payload = data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['probes'][_probe_pos]
                    target_key = {"label":payload.get('probe'),"wipen_type":payload['metadata'].get('_type')}
                    if( not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2) ):
                        data_set["nodes"].append({"label":payload.get('probe'), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})

                    if(any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                        _uuid = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                        _uuid = _uuid.get("uuid")
                    else:
                        _uuid = str(uuid.uuid4())
                    data_set["edges"].append({"label":sta_ssid, "source":payload['metadata'].get('_id'), "destination":_uuid})
        for _similar_ssid_pos, _similar_ssid in enumerate(data[_ssid]['similar_ssid']):
            _similar_ssid=next(iter(_similar_ssid))
            for _similar_ssid_bssid_pos, _similar_ssid_bssid in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid']):
                 for _client_pos, _client in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients']):
                    for _probe_pos, _probe in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['probes']):
                        payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['probes'][_probe_pos]
                        target_key = {"label":payload.get('probe'),"wipen_type":payload['metadata'].get('_type')}
                        if( not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2) ):
                            data_set["nodes"].append({"label":payload.get('probe'), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})
    
                        if(any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                            _uuid = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                            _uuid = _uuid.get("uuid")
                        else:
                            _uuid = str(uuid.uuid4())
                        data_set["edges"].append({"label":sta_ssid, "source":payload['metadata'].get('_id'), "destination":_uuid})


    with open('output', 'w') as f:
        f.write(json.dumps(data_set))
    print((data_set))


if __name__ == '__main__':
    import argparse
    import sys
    import json
    parser = argparse.ArgumentParser(prog=sys.argv[0],
            description='automated wireless pcap dissector',
            usage='sudo python3 wipen_to_wipen-ui.py -f [JSON]',
            add_help=True
    )

    parser.add_argument('-f', '--file',
        dest='json_filename',
        type=str,
        help='Provide one json to analysis',
    )

    # Basic error handling of the programs initalisation
    try:
        arg_test = sys.argv[1]
    except IndexError:
        parser.print_help()
        sys.exit(1)

    args, leftovers = parser.parse_known_args()

    with open(args.__dict__['json_filename']) as data_file:
        data = json.loads(data_file.read())

    result = populateNodes(data=data)
    

