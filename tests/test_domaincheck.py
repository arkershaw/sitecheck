import unittest
import domaincheck


class TestDomainCheck(unittest.TestCase):
    def setUp(self):
        # self.ipv6 = '2606:2800:220:1:248:1893:25c8:1946'
        # self.ipv4 = '93.184.216.34'
        # self.domain = 'example.com'

        self.ipv6 = '2404:6800:4005:810::2013'
        self.ipv4 = '172.217.163.243'
        self.domain = 'testsite.site-check.co.uk'

    def test_is_ip_address(self):
        self.assertTrue(domaincheck.is_ip_address(self.ipv6))
        self.assertTrue(domaincheck.is_ip_address(self.ipv4))
        self.assertFalse(domaincheck.is_ip_address(self.domain))
        self.assertFalse(domaincheck.is_ip_address(''))
        self.assertFalse(domaincheck.is_ip_address(None))
        self.assertFalse(domaincheck.is_ip_address(0.0))

    def test_get_name_and_address(self):
        name, address = domaincheck.get_name_and_address(self.ipv6)
        self.assertIsNotNone(name, self.domain)  # Reverse DNS
        self.assertEqual(address, self.ipv6)

        name, address = domaincheck.get_name_and_address(self.ipv4)
        self.assertIsNotNone(name, self.domain)
        self.assertEqual(address, self.ipv4)

        name, address = domaincheck.get_name_and_address(self.domain)
        self.assertEqual(name, self.domain)
        self.assertEqual(address, self.ipv4)

        name, address = domaincheck.get_name_and_address('http://{0}/test'.format(self.ipv4))
        self.assertIsNotNone(name, self.domain)
        self.assertEqual(address, self.ipv4)

        name, address = domaincheck.get_name_and_address('hdfs://{0}/test'.format(self.domain))
        self.assertIsNotNone(name, self.domain)
        self.assertEqual(address, self.ipv4)

        name, address = domaincheck.get_name_and_address('127.0.0.127')
        self.assertIsNone(name)
        self.assertEqual(address, '127.0.0.127')

        name, address = domaincheck.get_name_and_address('invalid')
        self.assertEqual(name, 'invalid')
        self.assertIsNone(address)


if __name__ == '__main__':
    unittest.main()
