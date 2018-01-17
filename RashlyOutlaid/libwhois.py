"""
 Copyright (c) 2014 Geir Skjotskift

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


import socket
from collections import namedtuple

try:
    text_type = unicode
    binary_type = str
except NameError:
    text_type = str
    binary_type = bytes


ASNRecord = namedtuple("ASNRecord", ["asn", "prefix", "asname", "cn", "isp", "peers"])


def astext(data):
    """
    Given a unicode/str/bytes always return str.

    We prefer to work with the 'native' string type for the version of python
    we run on, and this gets us that.
    """
    if isinstance(data, str):
        return data
    elif isinstance(data, text_type):
        return data.encode("utf-8", "ignore")
    elif isinstance(data, binary_type):
        return data.decode("utf-8", "ignore")
    raise TypeError('{!r} not a string'.format(data))


def asbinary(data):
    """
    Given a unicode/str/bytes always return a format suitable for sending on the
    wire or for use with file descriptors ope in 'b' mode.
    """
    if isinstance(data, text_type):
        return data.encode("utf-8")
    return data


class Whois(object):

    def __init__(self, address=None, port=43, timeout=30):
        self.address = address
        self.port = port
        self.timeout = timeout
        self._connection = None
        self.buffer = ""

    def connect(self):
        self._connection = socket.create_connection((self.address, self.port), self.timeout)

    def send(self, query):
        self._connection.send(b"".join([query, b"\n"]))

    def read(self):
        self.buffer = ""
        while 1:
            data = self._connection.recv(1024)
            if not data:
                self._connection.close()
                return
            self.buffer += astext(data)


class ASNWhois(Whois):

    def __init__(self, address="asn.shadowserver.org", port=43, timeout=30):
        super(ASNWhois, self).__init__(address=address, port=port, timeout=timeout)
        self._query = ""
        self._result = {}
        self._peers = False
        self._multiple = False
        self._base_idx = 0

    def get_result(self):
        if self._result: return self._result
        self._perform_query()
        self._base_idx = 0
        if self._multiple:
            self._base_idx += 1
        if self.peers:
            self._base_idx += 1
        self._result = {}
        for line in self.buffer.split('\n'):
            elements = [element.strip() for element in line.split('|')]
            if not len(elements) >= 6: continue # empty lines
            asdata = elements[self._base_idx:]
            if self.peers:
                asdata.append(elements[self._base_idx - 1].split())
            else:
                asdata.append([])
            if self._multiple and self._peers:
                query = elements[self._base_idx - 2]
            elif self._multiple:
                query = elements[self._base_idx - 1]
            else:
                query = self.query
            self._result[astext(query)] = ASNRecord(*asdata)
        return self._result

    def set_result(self, vals):
        raise QueryError("Read only property: Result")

    def set_peers(self, peers):
        if not isinstance(peers, bool):
            raise QueryError("peers property must be either True or False")
        self._result = {}
        self._peers = peers

    def get_peers(self):
        return self._peers

    def set_query(self, query):
        self._query = query
        self._result = {}

    def _perform_query(self):
        if not self._query: raise QueryError("Trying to perform empty query")
        if isinstance(self.query, text_type) or isinstance(self.query, binary_type):
            self._multiple = False
            self._query_single()
        elif isinstance(self.query, list):
            self._multiple = True
            self._query_multiple()
        else:
            raise QueryError("Need string or list of strings")

    def get_query(self):
        return self._query

    def _query_single(self):
        if not is_ip(self.query): raise QueryError("Not an IPv4 address " + self.query)
        self.connect()
        if self.peers:
            self.send(b" ".join([b"peer", asbinary(self._query)]))
        else:
            self.send(b" ".join([b"origin", asbinary(self._query)]))
        self.read()

    def _query_multiple(self):
        self.connect()
        if self.peers:
            self.send(b"begin peer")
        else:
            self.send(b"begin origin")
        for query in self._query:
            if not is_ip(query):
                self._connection.close()
                raise QueryError("Not an IPv4 address " + query)
            self.send(asbinary(query))
        self.send(b"end")
        self.read()

    result = property(get_result, set_result)
    peers = property(get_peers, set_peers)
    query = property(get_query, set_query)


def is_ip(data):
    if not isinstance(data, text_type) and not isinstance(data, binary_type): return False
    data = astext(data)
    elements = data.strip().split(".")
    if not len(elements) == 4: return False
    for c, t in enumerate(elements):
        try:
            v = int(t)
            if not ((c > 0 and v >= 0 and v < 256) or (c == 0 and v >= 1 and c < 256)): return False
        except ValueError:
            return False
    return True

class QueryError(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)
