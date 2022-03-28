from cmath import rect
import unittest
import main
from datetime import datetime, timedelta
import subprocess
from shutil import copyfile
from scapy.all import *


class TestParseLine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        copyfile("./user.rules_orig", "./user.rules")

        with open('./recorded_addrs_file.json', "w") as file:
            file.write("{}")

    @classmethod
    def tearDownClass(cls):
        copyfile("./user.rules_orig", "./user.rules")

        with open('./recorded_addrs_file.json', "w") as file:
            file.write("{}")

    def test_analyze_network(self):
        """
        Test tests the overall script
        """
        expected = {'192.168.100.144 -> 192.168.100.123': [{'port': 222, 'time': '2022-03-28T01:15:01.712185'}]}
        pkt = IP(dst="192.168.100.123", src="192.168.100.144") / TCP(sport=333, dport=222,
                                                                     seq=112344) / "Sequence number 112344"

        ips_arr = main.analyze_network(pkt)
        print(ips_arr)
        self.assertTrue(len(ips_arr) == len(expected))

    def test_ports_scanned_detector(self):
        """
        Test tests if the port scanner is working correctly
        """
        now = datetime.now()
        last_min = now - timedelta(minutes=1)
        last_two_min = now - timedelta(minutes=2)

        recorded_addrs = {
            "1.1.1.1 -> 2.2.2.2": [
                {"port": "80", "time": now.isoformat()},
                {"port": "81", "time": now.isoformat()},
                {"port": "82", "time": now.isoformat()},
            ]}

        scanned_ports = main.ports_scanned_detector(recorded_addrs["1.1.1.1 -> 2.2.2.2"])
        self.assertTrue(len(scanned_ports) == 3)

        recorded_addrs = {
            "1.1.1.1 -> 2.2.2.2": [
                {"port": "80", "time": now.isoformat()},
                {"port": "81", "time": last_min.isoformat()},
                {"port": "82", "time": last_two_min.isoformat()},
            ]}

        scanned_ports = main.ports_scanned_detector(recorded_addrs["1.1.1.1 -> 2.2.2.2"])
        self.assertTrue(len(scanned_ports) == 0)

    def test_new_connection(self):
        """
        Test tests the new connection gets added correctly
        """

        ips = main.new_connection({}, "1.1.1.1", "80", "2.2.2.2", "3000")
        print(ips)
        self.assertTrue(len(ips) == 1)
        self.assertTrue(len(ips["1.1.1.1 -> 2.2.2.2"]) == 1)
        self.assertTrue(ips["1.1.1.1 -> 2.2.2.2"][0]["port"] == "3000")

    def test_block_ip_ufw(self):
        """
        Test tests the new connection gets added correctly
        """

        # Verify
        found1 = False
        found2 = False
        with open('./user.rules') as file:
            if 'deny any any 0.0.0.0/0 any 1.1.1.1 in' in file.read():
                found1 = True
            if '-A ufw-user-input -s 1.1.1.1 -j DROP' in file.read():
                found2 = True
        self.assertFalse(found1 and found2)

        # Test
        main.block_ip_ufw("1.1.1.1", path="./user.rules")
        found = False
        with open('./user.rules') as file:
            if 'deny any any 0.0.0.0/0 any 1.1.1.1 in' in file.read():
                found = True

        self.assertTrue(found)

    def test_interpret_packet(self):
        """
        Test tests that the packet is interpreted correctly
        """

        pkt = IP(dst="192.168.100.123", src="192.168.100.144") / TCP(sport=333, dport=222,
                                                                     seq=112344) / "Sequence number 112344"
        from_ip, from_port, to_ip, to_port = main.interpret_packet(pkt)
        self.assertTrue(to_ip == "192.168.100.123")
        self.assertTrue(from_ip == "192.168.100.144")
        self.assertTrue(to_port == 222)
        self.assertTrue(from_port == 333)

    def test_integration_port_scan(self):
        """
        Test tests the whole program
        """

        pkt = IP(dst="192.168.100.123", src="192.168.100.144") / TCP(sport=333, dport=222,
                                                                     seq=112344) / "Sequence number 112344"
        ips = main.analyze_network(pkt, firewall_location="./user.rules")
        pkt = IP(dst="192.168.100.123", src="192.168.100.144") / TCP(sport=333, dport=223,
                                                                     seq=112344) / "Sequence number 112344"
        ips = main.analyze_network(pkt, firewall_location="./user.rules")
        pkt = IP(dst="192.168.100.123", src="192.168.100.144") / TCP(sport=333, dport=224,
                                                                     seq=112344) / "Sequence number 112344"
        ips = main.analyze_network(pkt, firewall_location="./user.rules")

        # Verify firewall rule has been changed
        found = False
        with open('./user.rules') as file:
            if 'deny any any 0.0.0.0/0 any 192.168.100.144 in' in file.read():
                found = True

        self.assertTrue(found)

    def test_integration_not_port_scan(self):
        """
        Test tests the whole program
        """

        pkt = IP(dst="192.168.100.123", src="192.168.100.144") / TCP(sport=333, dport=222,
                                                                     seq=112344) / "Sequence number 112344"
        ips = main.analyze_network(pkt, firewall_location="./user.rules")
        pkt = IP(dst="192.168.100.123", src="192.168.100.144") / TCP(sport=333, dport=223,
                                                                     seq=112344) / "Sequence number 112344"
        ips = main.analyze_network(pkt, firewall_location="./user.rules")

        # Verify firewall rule has been changed
        found = False
        with open('./user.rules') as file:
            if 'deny any any 0.0.0.0/0 any 192.168.100.144 in' in file.read():
                found = True

        self.assertFalse(found)


if __name__ == '__main__':
    unittest.main()
