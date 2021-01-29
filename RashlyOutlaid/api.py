""" Copyright (c) 2014-2021 Geir Skjotskift

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
"""

from collections import namedtuple
from typing import Dict, List, Text, Any
import datetime

import requests

import RashlyOutlaid

ASNRecord = namedtuple('ASNRecord',
                       ['asn', 'prefix', 'asname', 'cn', 'isp', 'peers'])
AVRecord = namedtuple('AVRecord', ['md5', 'vendor', 'signature', 'timestamp'])
MalwareRecord = namedtuple('MalwareRecord',
                           ['timestamp',
                            'first_seen',
                            'last_seen',
                            'type',
                            'sha256',
                            'md5',
                            'sha1',
                            'pehash',
                            'tlsh',
                            'import_hash',
                            'entropy',
                            'filesize',
                            'adobe_malware_classifier',
                            'magic',
                            'anti_virus'])


def parse_shadowserver_time(time_string: Text) -> datetime.datetime:
    """Parse a date on the format '2018-10-17 20:36:23'"""

    try:
        return datetime.datetime.strptime(time_string[:19], '%Y-%m-%d %H:%M:%S')
    except:
        print(time_string)
        raise


def malware(hashes: List[Text], **kwargs_requests: Any) -> List[MalwareRecord]:
    """Lookup the list of hashes using the Shadowserver malware API

    You can pass arguments to requests suchs as proxies:

    api.malware(["4b21f25e02b0d1df86ab745f82e140ab1cc498af"],
                proxies={'http': 'http://myproxy.example.com:8080',
                         'https': 'http://myproxy.example.com:8080'
                        })

    https://www.shadowserver.org/what-we-do/network-reporting/api-asn-and-network-queries/
    """

    url = (f'https://api.shadowserver.org/malware/info'
           f'?sample={",".join(hashes)}')

    res = requests.get(url, **kwargs_requests)

    if res.status_code != 200:
        msg = (f"RashlyOutlaid.api.malware could not lookup {hashes}. "
               f"Got status='{res.status_code}' while requesing '{url}'")
        raise RashlyOutlaid.libwhois.QueryError(msg)

    ss_data: Dict = res.json()
    return [MalwareRecord(parse_shadowserver_time(elem["timestamp"]),
                          parse_shadowserver_time(elem["first_seen"]),
                          parse_shadowserver_time(elem["last_seen"]),
                          elem.get("type"),
                          elem.get("sha256"),
                          elem.get("md5"),
                          elem.get("sha1"),
                          elem.get("pehash"),
                          elem.get("tlsh"),
                          elem.get("import_hash"),
                          elem.get("entropic"),
                          elem.get("filesize"),
                          elem.get("adobe_malware_classifier"),
                          elem.get("magic"),
                          [AVRecord(x.get("md5"),
                                    x.get("vendor"),
                                    x.get("signature"),
                                    parse_shadowserver_time(x["timestamp"]))
                           for x in elem["anti_virus"]])
            for elem in ss_data]


def _map_shadowserver_model(ssdata: List[Dict]) -> List[ASNRecord]:
    """Map the result from shadowserver to a list of ASNRecords"""

    return [ASNRecord(x['asn'],
                      x['prefix'] if 'prefix' in x else '',
                      x['asname_short'],
                      x['geo'],
                      x['asname_long'],
                      x['peer'].split() if 'peer' in x else [])
            for x in ssdata]


def origin(ip_addresses: List, **kwargs_requests: Any) -> List[ASNRecord]:
    """Lookup the list of ip addresses vs the Shadowserver origin web api
    https://www.shadowserver.org/what-we-do/network-reporting/api-asn-and-network-queries/

    You can pass arguments to requests suchs as proxies:

    api.origin(["8.8.8.8"],
                proxies={'http': 'http://myproxy.example.com:8080',
                         'https': 'http://myproxy.example.com:8080'
                        })

    """

    url = (f"https://api.shadowserver.org/net/asn"
           f"?origin={','.join(ip_addresses)}")

    res = requests.get(url, **kwargs_requests)

    if res.status_code != 200:
        msg = (f"RashlyOutlaid.api.origin could not loopup origin. "
               f"Got status='{res.status_code}' while requesing '{url}'")
        raise RashlyOutlaid.libwhois.QueryError(msg)

    ss_data: List[Dict] = res.json()
    return _map_shadowserver_model(ss_data)


def peer(ip_addresses: List, **kwargs_requests: Any) -> List[ASNRecord]:
    """Lookup the list of ip addresses vs the Shadowserver peer web api
    https://www.shadowserver.org/what-we-do/network-reporting/api-asn-and-network-queries/

    You can pass arguments to requests suchs as proxies:

    api.peer(["8.8.8.8"],
             proxies={'http': 'http://myproxy.example.com:8080',
                      'https': 'http://myproxy.example.com:8080'
                     })

    """

    url = (f"https://api.shadowserver.org/net/asn"
           f"?peer={','.join(ip_addresses)}")

    res = requests.get(url, **kwargs_requests)

    if res.status_code != 200:
        msg = (f"RashlyOutlaid.api.peer could not loopup peers "
               f"of {ip_addresses}. "
               f"Got status='{res.status_code}' while requesing '{url}'")
        raise RashlyOutlaid.libwhois.QueryError(msg)

    ss_data: List[Dict] = res.json()
    return _map_shadowserver_model(ss_data)


def asn(asnumber: int, **kwargs_requests) -> List[ASNRecord]:
    """Lookup the asn via the Shadowserver asn web api
    https://www.shadowserver.org/what-we-do/network-reporting/api-asn-and-network-queries/

    You can pass arguments to requests suchs as proxies:

    api.asn(12345,
            proxies={'http': 'http://myproxy.example.com:8080',
                     'https': 'http://myproxy.example.com:8080'
                    })
    """

    url = (f"https://api.shadowserver.org/net/asn"
           f"?query={asnumber}")

    res = requests.get(url, **kwargs_requests)

    if res.status_code != 200:
        msg = (f"RashlyOutlaid.api.asn could not loopup asn {asnumber}. "
               f"Got status='{res.status_code}' while requesing '{url}'")
        raise RashlyOutlaid.libwhois.QueryError(msg)

    ss_data: List[Dict] = [res.json()]
    return _map_shadowserver_model(ss_data)


def prefix(asnumber: int, **kwargs_requests: Any) -> List[Text]:
    """Lookup the list of ip addresses vs the Shadowserver prefix web api
    https://www.shadowserver.org/what-we-do/network-reporting/api-asn-and-network-queries/

    You can pass arguments to requests suchs as proxies:

    api.prefix(12345,
               proxies={'http': 'http://myproxy.example.com:8080',
                        'https': 'http://myproxy.example.com:8080'
                       })
    """

    url = (f"https://api.shadowserver.org/net/asn"
           f"?prefix={asnumber}")

    res = requests.get(url, **kwargs_requests)

    if res.status_code != 200:
        msg = (f"RashlyOutlaid.api.prefix could not loopup asn {asnumber}. "
               f"Got status='{res.status_code}' while requesing '{url}'")
        raise RashlyOutlaid.libwhois.QueryError(msg)

    ss_data: List[Text] = res.json()
    return ss_data
