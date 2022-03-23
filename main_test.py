from cmath import rect
import unittest
import main
import os
import datetime

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
        ip, port = main.translate_addr_from_hex("0100007F:0050")
        self.assertTrue(ip == "127.0.0.1")
        self.assertTrue(port == "80")

        ip, port = main.translate_addr_from_hex("E10FA20A:01BB")
        self.assertTrue(ip == "10.162.15.225")
        self.assertTrue(port == "443")


    def test_main(self):
        """
        Test tests the overall script
        """
        expected = {'0.0.0.0 -> 0.0.0.0': [{'port': '0', 'time': '2022-03-23T17:10:15.210714'}, {'port': '0', 'time': '2022-03-23T17:11:19.892583'}, {'port': '0', 'time': '2022-03-23T17:12:03.766865'}, {'port': '0', 'time': '2022-03-23T17:12:26.136686'}, {'port': '0', 'time': '2022-03-23T17:12:42.920784'}, {'port': '0', 'time': '2022-03-23T17:12:54.028049'}, {'port': '0', 'time': '2022-03-23T17:13:07.644678'}, {'port': '0', 'time': '2022-03-23T17:13:11.540622'}, {'port': '0', 'time': '2022-03-23T17:14:11.977793'}, {'port': '0', 'time': '2022-03-23T17:14:18.559547'}, {'port': '0', 'time': '2022-03-23T17:14:23.997305'}, {'port': '0', 'time': '2022-03-23T17:14:27.476064'}, {'port': '0', 'time': '2022-03-23T17:14:32.611137'}, {'port': '0', 'time': '2022-03-23T17:14:36.834874'}, {'port': '0', 'time': '2022-03-23T17:14:59.774272'}, {'port': '0', 'time': '2022-03-23T17:15:04.342989'}], '127.0.0.1 -> 0.0.0.0': [{'port': '0', 'time': '2022-03-23T17:13:41.710872'}], '127.0.0.53 -> 0.0.0.0': [{'port': '0', 'time': '2022-03-23T17:14:56.196107'}], '10.162.15.225 -> 91.189.91.15': [{'port': '80', 'time': '2022-03-23T17:15:07.800449'}], '10.162.15.225 -> 172.217.13.110': [{'port': '80', 'time': '2022-03-23T17:15:07.801831'}], '10.162.15.225 -> 169.254.169.254': [{'port': '80', 'time': '2022-03-23T17:15:07.805942'}], '10.162.15.225 -> 91.189.88.152': [{'port': '80', 'time': '2022-03-23T17:15:07.808677'}], '10.162.15.225 -> 91.189.92.20': [{'port': '443', 'time': '2022-03-23T17:15:07.804903'}], '10.162.15.225 -> 91.189.91.42': [{'port': '443', 'time': '2022-03-23T17:15:07.806780'}], '10.162.15.225 -> 204.225.215.59': [{'port': '55627', 'time': '2022-03-23T17:15:07.807522'}], '10.162.15.225 -> 91.189.88.179': [{'port': '443', 'time': '2022-03-23T17:15:07.809118'}]}

        filename = os.path.join(os.path.dirname(__file__), "proc_net_tcp.txt")
        ips_arr = main.analyze_file(filename)
        self.assertTrue(len(ips_arr) == len(expected))

    def test_ports_scanned_detector(self):
        """
        Test tests if the port scanner is working correctly
        """
        now = datetime.datetime.now()
        last_min = now - datetime.timedelta(minutes=1)
        last_two_min = now - datetime.timedelta(minutes=2)
        print(type(last_min))
        recorded_addrs = {
            "1.1.1.1 -> 2.2.2.2": [
                    {"port": "80", "time":now.isoformat()},                    
                    {"port": "81", "time":now.isoformat()},
                    {"port": "82", "time":now.isoformat()},                     
                ]}

        scanned_ports = main.ports_scanned_detector(recorded_addrs["1.1.1.1 -> 2.2.2.2"])
        self.assertTrue(len(scanned_ports) == 3)

        recorded_addrs = {
            "1.1.1.1 -> 2.2.2.2": [
                    {"port": "80", "time":now.isoformat()},                    
                    {"port": "81", "time":last_min.isoformat()},
                    {"port": "82", "time":last_two_min.isoformat()},                     
                ]}

        scanned_ports = main.ports_scanned_detector(recorded_addrs["1.1.1.1 -> 2.2.2.2"])
        self.assertTrue(len(scanned_ports) == 0)

if __name__ == '__main__':
    unittest.main()