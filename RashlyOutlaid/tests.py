import unittest

from RashlyOutlaid.libwhois import ASNWhois


class TestWhois(unittest.TestCase):

    def test_query(self):
        asnwhois = ASNWhois()
        asnwhois.query = "212.58.245.94"
        asnwhois.peers = True
        result = asnwhois.result["212.58.245.94"]

        self.assertEqual(result.asn, "2818")
        self.assertTrue(isinstance(result.asn, str))
        self.assertEqual(result.prefix, "212.58.224.0/19")
        self.assertTrue(isinstance(result.prefix, str))
        self.assertEqual(result.asname, "BBC")
        self.assertTrue(isinstance(result.asname, str))
        self.assertEqual(result.cn, "GB")
        self.assertTrue(isinstance(result.cn, str))
        self.assertEqual(result.isp, "BBC Internet Services, UK, GB")
        self.assertTrue(isinstance(result.isp, str))
        self.assertEqual(result.peers, ["286", "1299", "3356"])
        self.assertTrue(isinstance(result.peers[0], str))

    def test_query_str(self):
        asnwhois = ASNWhois()
        asnwhois.query = b"212.58.245.94"
        asnwhois.peers = True
        result = asnwhois.result["212.58.245.94"]

        self.assertEqual(result.asn, "2818")
        self.assertTrue(isinstance(result.asn, str))
        self.assertEqual(result.prefix, "212.58.224.0/19")
        self.assertTrue(isinstance(result.prefix, str))
        self.assertEqual(result.asname, "BBC")
        self.assertTrue(isinstance(result.asname, str))
        self.assertEqual(result.cn, "GB")
        self.assertTrue(isinstance(result.cn, str))
        self.assertEqual(result.isp, "BBC Internet Services, UK, GB")
        self.assertTrue(isinstance(result.isp, str))
        self.assertEqual(result.peers, ["286", "1299", "3356"])
        self.assertTrue(isinstance(result.peers[0], str))

    def test_query_unicode(self):
        asnwhois = ASNWhois()
        asnwhois.query = u"212.58.245.94"
        asnwhois.peers = True
        result = asnwhois.result["212.58.245.94"]

        self.assertEqual(result.asn, "2818")
        self.assertTrue(isinstance(result.asn, str))
        self.assertEqual(result.prefix, "212.58.224.0/19")
        self.assertTrue(isinstance(result.prefix, str))
        self.assertEqual(result.asname, "BBC")
        self.assertTrue(isinstance(result.asname, str))
        self.assertEqual(result.cn, "GB")
        self.assertTrue(isinstance(result.cn, str))
        self.assertEqual(result.isp, "BBC Internet Services, UK, GB")
        self.assertTrue(isinstance(result.isp, str))
        self.assertEqual(result.peers, ["286", "1299", "3356"])
        self.assertTrue(isinstance(result.peers[0], str))

    def test_query_list(self):
        asnwhois = ASNWhois()
        asnwhois.query = ["212.58.245.94"]
        asnwhois.peers = True
        result = asnwhois.result["212.58.245.94"]

        self.assertEqual(result.asn, "2818")
        self.assertTrue(isinstance(result.asn, str))
        self.assertEqual(result.prefix, "212.58.224.0/19")
        self.assertTrue(isinstance(result.prefix, str))
        self.assertEqual(result.asname, "BBC")
        self.assertTrue(isinstance(result.asname, str))
        self.assertEqual(result.cn, "GB")
        self.assertTrue(isinstance(result.cn, str))
        self.assertEqual(result.isp, "BBC Internet Services, UK, GB")
        self.assertTrue(isinstance(result.isp, str))
        self.assertEqual(result.peers, ["286", "1299", "3356"])
        self.assertTrue(isinstance(result.peers[0], str))

    def test_query_list_b(self):
        asnwhois = ASNWhois()
        asnwhois.query = [b"212.58.245.94"]
        asnwhois.peers = True
        result = asnwhois.result["212.58.245.94"]

        self.assertEqual(result.asn, "2818")
        self.assertTrue(isinstance(result.asn, str))
        self.assertEqual(result.prefix, "212.58.224.0/19")
        self.assertTrue(isinstance(result.prefix, str))
        self.assertEqual(result.asname, "BBC")
        self.assertTrue(isinstance(result.asname, str))
        self.assertEqual(result.cn, "GB")
        self.assertTrue(isinstance(result.cn, str))
        self.assertEqual(result.isp, "BBC Internet Services, UK, GB")
        self.assertTrue(isinstance(result.isp, str))
        self.assertEqual(result.peers, ["286", "1299", "3356"])
        self.assertTrue(isinstance(result.peers[0], str))

    def test_query_list_u(self):
        asnwhois = ASNWhois()
        asnwhois.query = [u"212.58.245.94"]
        asnwhois.peers = True
        result = asnwhois.result["212.58.245.94"]

        self.assertEqual(result.asn, "2818")
        self.assertTrue(isinstance(result.asn, str))
        self.assertEqual(result.prefix, "212.58.224.0/19")
        self.assertTrue(isinstance(result.prefix, str))
        self.assertEqual(result.asname, "BBC")
        self.assertTrue(isinstance(result.asname, str))
        self.assertEqual(result.cn, "GB")
        self.assertTrue(isinstance(result.cn, str))
        self.assertEqual(result.isp, "BBC Internet Services, UK, GB")
        self.assertTrue(isinstance(result.isp, str))
        self.assertEqual(result.peers, ["286", "1299", "3356"])
        self.assertTrue(isinstance(result.peers[0], str))
