RashlyOutlaid
=============

Library to interact with the [shadowserver](https://www.shadowserver.org) API and ASN whois services.

about
-----

 Performs api or whois queries against api.shadowserver.org and
asn.shadowserver.org.  If you query for a list of IP-addresses the library will
perform a properly formated bulk query as described and required by the
Shadowserver foundation.

install
-------

```bash
# python3 -m pip install RashlyOutlaid
```

shadowserver service
--------------------

- The API is rate limited. At this time of writing (January 2021) the current
limit is is set to 10 queries per second. Verify the current limits on
[The Shadowserver API](https://www.shadowserver.org/what-we-do/network-reporting/api-asn-and-network-queries/)

- [The Shadowswerver IP-BGP Service](http://wiki.shadowserver.org/wiki/pmwiki.php/Services/IP-BGP)

Example
-------

```python
>>> import RashlyOutlaid.api as shadowserver
>>> from pprint import pprint as pp
>>> pp(shadowserver.prefix(22414))
['208.82.236.0/22']
>>> pp(shadowserver.asn(109))
[ASNRecord(asn='109', prefix='', asname='CISCOSYSTEMS', cn='US', isp='CISCOSYSTEMS', peers=[])]
>>> pp(shadowserver.origin(["8.8.8.8", "8.8.4.4", "4.2.2.4"]))
[ASNRecord(asn='15169', prefix='8.8.8.0/24', asname='GOOGLE', cn='US', isp='GOOGLE', peers=[]),
 ASNRecord(asn='15169', prefix='8.8.4.0/24', asname='GOOGLE', cn='US', isp='GOOGLE', peers=[]),
 ASNRecord(asn='3356', prefix='4.0.0.0/9', asname='LEVEL3', cn='US', isp='LEVEL3', peers=[])]
>>> pp(shadowserver.peer(["8.8.8.8", "8.8.4.4", "4.2.2.4"]))
[ASNRecord(asn='15169', prefix='8.8.8.0/24', asname='GOOGLE', cn='US', isp='GOOGLE', peers=['1101', '6696', '47605', '51088']),
 ASNRecord(asn='15169', prefix='8.8.4.0/24', asname='GOOGLE', cn='US', isp='GOOGLE', peers=['1101', '6696', '47605', '51088']),
 ASNRecord(asn='3356', prefix='4.0.0.0/9', asname='LEVEL3', cn='US', isp='LEVEL3', peers=['2914', '6453', '6461', '47605'])]
>>>
>>> for r in shadowserver.malware(["dfe1832e02888422f48d6896dc8e8f73","d41d8cd98f00b204e9800998ecf8427e"]):
...    print(f"{r.sha1} First Seen: {r.first_seen.year}")
...    for av in r.anti_virus:
...       print(f"{av.vendor} {av.signature} {av.timestamp.year}")
...
c56ba498d41caa7be3c1eb5588cec27c413eb208 First Seen: 2016
Fortinet W32/Lamer.CQ 2017
Avast Win32:Lamer-A 2018
AVG Win32.Generic.VC 2016
Avast Win32:Malware-gen 2018
K7GW Virus ( 004d554e1 ) 2016
MicroWorld Gen:Win32.FileInfector.uwZ@a4T!Kcmi 2017
Sophos Troj/Agent-APCU 2018
Eset Win32/Zatoxp.C 2018
K7 Virus ( 004d554e1 ) 2016
Avast Win32:Malware-gen 2018
Avira TR/Dropper.Gen8 2016
BitDefender Gen:Win32.Backdoor.ozZbauKWKdpb 2018
DrWeb Win32.HLLW.Siggen.4657 2018
K7GW Virus ( 004d554e1 ) 2016
AhnLab Trojan/Win32.FileInfector 2018
AhnLab Trojan/Win32.FileInfector 2018
QuickHeal W32.Sivis.A5 2017
Clam PUA.Win.Packer.Purebasic-2 2017
BitDefender Gen:Win32.FileInfector.uwZ@a4T!Kcmi 2017
AVG Win32.Generic.VC 2016
Ikarus Gen.Win32.FileInfector 2018
BitDefender Trojan.PWS.Onlinegames.KEGA 2018
BitDefender Trojan.GenericKD.40542465 2018
BitDefender Gen:Win32.FileInfector.uwZ@a4T!Kcmi 2017
Clam PUA.Win.Packer.Purebasic-2 2017
Sunbelt Virus.Win32.sivis.a 2018
da39a3ee5e6b4b0d3255bfef95601890afd80709 First Seen: 2015
>>>

```
