RashlyOutlaid
=============

Perform ASN whois queries against shadowserver.org

about
-----

 Performs whois queries against asn.shadowserver.org. If you query for a list of IP-addresses the library will perform a properly formated bulk query as described and required by the Shadowserver foundation.

The result is cached. If the peers property or the query property is changed, a new query will be executed when the result property is called. Subsequent calls to .result will only access the cached result. 

shadowserver service
--------------------

http://www.shadowserver.org/wiki/pmwiki.php/Services/IP-BGP

Example
-------

```python
>>> from RashlyOutlaid.libwhois import ASNWhois
>>> asnwhois = ASNWhois()
>>> asnwhois.query = ["212.58.246.94", "94.229.76.35"]
>>> asnwhois.peers = True
>>> asnwhois.result["212.58.246.94"]
ASNRecord(asn='2818', prefix='212.58.224.0/19', asname='BBC', cn='GB', domain='BBC.CO.UK', isp='BBC', peers=['3356', '7473', '9031', '31133', '37105', '51088'])
>>> for q, r in asnwhois.result.items():
...    print q, r.cn, r.domain
...
94.229.76.35 GB UKSERVERS.COM
212.58.246.94 GB BBC.CO.UK
>>>
```