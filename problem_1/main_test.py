import unittest
import main
import os

class TestParseLine(unittest.TestCase):
    def test_parse_line(self):
        """
        Test tests that the correct to/from ip address is returned
        """
        line = "   0: 00000000:1F99 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 30876 1 0000000000000000 100 0 0 10 0"
        from_ip, to_ip = main.parse_line(line)
        self.assertTrue(from_ip == "00000000:1F99")
        self.assertTrue(to_ip == "00000000:0000")

        line = "  11: E10FA20A:CCA0 6E0DD9AC:0050 06 00000000:00000000 03:00001211 00000000     0        0 0 3 0000000000000000"
        from_ip, to_ip = main.parse_line(line)
        self.assertTrue(from_ip == "E10FA20A:CCA0")
        self.assertTrue(to_ip == "6E0DD9AC:0050")

    def test_translate_addr_from_hex(self):
        """
        Test tests that the ip address is translated from hex correctly
        """
        ip_addr = main.translate_addr_from_hex("0100007F:0050")
        self.assertTrue(ip_addr == "127.0.0.1:80")

        ip_addr = main.translate_addr_from_hex("E10FA20A:01BB")
        self.assertTrue(ip_addr == "10.162.15.225:443")


    def test_seen_before(self):
        """
        Test tests if the ip address is returned as "new" correctly
        """
        ips_arr = ["0.0.0.0:80 -> 0.0.0.0:80"]
        self.assertFalse(main.seen_before("0.0.0.0:80", "1.1.1.1:80", ips_arr))

        ips_arr = ["0.0.0.0:80 -> 0.0.0.0:80"]
        self.assertTrue(main.seen_before("0.0.0.0:80", "0.0.0.0:80", ips_arr))

        ips_arr = ["0.0.0.0:80 -> 0.0.0.0:80", "0.0.0.0:80 -> 1.1.1.1:80"]
        self.assertTrue(main.seen_before("0.0.0.0:80", "1.1.1.1:80", ips_arr))

        ips_arr = []
        self.assertFalse(main.seen_before("0.0.0.0:80", "1.1.1.1:80", ips_arr))

    def test_read_file(self):
        """
        Test tests the overall script
        """
        expected = ['0.0.0.0:8089 -> 0.0.0.0:0', '0.0.0.0:57337 -> 0.0.0.0:0', '0.0.0.0:48603 -> 0.0.0.0:0', '0.0.0.0:2049 -> 0.0.0.0:0', '127.0.0.1:33415 -> 0.0.0.0:0', '0.0.0.0:39115 -> 0.0.0.0:0', '0.0.0.0:111 -> 0.0.0.0:0', '0.0.0.0:45845 -> 0.0.0.0:0', '127.0.0.53:53 -> 0.0.0.0:0', '0.0.0.0:22 -> 0.0.0.0:0', '10.162.15.225:36088 -> 91.189.91.15:80', '10.162.15.225:52384 -> 172.217.13.110:80', '10.162.15.225:56346 -> 169.254.169.254:80', '10.162.15.225:56350 -> 169.254.169.254:80', '10.162.15.225:55476 -> 91.189.88.152:80', '10.162.15.225:44396 -> 91.189.92.20:443', '10.162.15.225:56348 -> 169.254.169.254:80', '10.162.15.225:58612 -> 91.189.91.42:443', '10.162.15.225:22 -> 204.225.215.59:55627', '10.162.15.225:59046 -> 91.189.88.179:443', '10.162.15.225:55474 -> 91.189.88.152:80', '10.162.15.225:55474 -> 91.189.88.179:443']

        filename = os.path.join(os.path.dirname(__file__), "proc_net_tcp.txt")
        ips_arr = main.read_file(filename)
        self.assertTrue(len(ips_arr) == len(expected))
        self.assertTrue(ips_arr == expected)

if __name__ == '__main__':
    unittest.main()