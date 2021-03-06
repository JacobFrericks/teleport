from prometheus_client import Counter, start_http_server
import socket
import struct
import time
import json
from datetime import datetime
from scapy.all import *

c = Counter('new_network_hits', 'New Network Hits')
recorded_addrs_file = './recorded_addrs_file.json'


def analyze_network(pkt, firewall_location="/firewall/user.rules"):
    """Reads the given file and outputs all new connections

    Keyword arguments:
    path -- (optional) The path to the file to read
    ip_arr -- (optional) The in-memory array that stores all seen connections
    """
    # Load from file
    # Opening JSON file
    with open(recorded_addrs_file) as json_file:
        ips = json.load(json_file)

    from_ip, from_port, to_ip, to_port = interpret_packet(pkt)
    if from_ip == "" or to_port == "":
        return ""

    # Port scan
    fmt_str = "{} -> {}".format(from_ip, to_ip)
    for ip in ips:
        if fmt_str == ip:
            # Save connection for future reference
            # Technically this is not a new connection, so we will not output it. However, for port scanning to work,
            # we need to save the IP and the port
            new_connection(ips, from_ip, from_port, to_ip, to_port, output=False)

            scanned_ports = ports_scanned_detector(ips[fmt_str])
            if scanned_ports:
                block_ip_ufw(from_ip, firewall_location)
                print("Port scan detected: {} -> {} on ports {}".format(from_ip, to_ip, scanned_ports))
            break
        else:
            # Save connection for future reference
            new_connection(ips, from_ip, from_port, to_ip, to_port)
            break
    else:
        # Save connection for future reference
        new_connection(ips, from_ip, from_port, to_ip, to_port)
    return ips


def ports_scanned_detector(port_times):
    """Detects if ports are being scanned

    Returns an array of ports scanned, if a scan is detected.
    A scan has been detected if the same from_ip and to_ip are being hit
    but the to_ports are different, and three or more different ports were hit in less than 60 seconds

    Keyword arguments:
    port_times -- An array of objects containing the ports that were hit, and the iso timestamp they were hit
                  For example: {"port": 80, "time": 2022-03-25T22:46:41+0000}
    """
    new_date = datetime.now()
    ports_scanned_in_last_min = []
    for obj in port_times:
        if obj["port"] not in ports_scanned_in_last_min:
            old_date = datetime.fromisoformat(obj["time"])
            date_diff = new_date - old_date
            if date_diff.total_seconds() <= 60:
                ports_scanned_in_last_min.append(obj["port"])
    if len(ports_scanned_in_last_min) >= 3:
        return ports_scanned_in_last_min
    return []


def get_now():
    """Returns the current time in datetime's iso format"""
    return datetime.now().isoformat()


def new_connection(ips, from_ip, from_port, to_ip, to_port, output=True):
    """Prints, saves, and counts a new connection

    This will print out a new connection "New connection: 1.1.1.1:80 -> 2.2.2.2:80"
    This will also save the new connection into ips
    This will also count the new connection for Prometheus metrics

    Keyword arguments:
    ips -- The place to store all new connections
    from_ip -- The IP address where the connection is coming from
    from_port -- The port where the connection is coming from
    to_ip -- The IP address where the connection is going to
    to_port -- The port where the connection is going to
    output -- Determines if it should be printed to the console or counted for prometheus
    """
    fmt_str = "{} -> {}".format(from_ip, to_ip)

    if fmt_str not in ips:
        ips[fmt_str] = []
    ips[fmt_str].append({"port": to_port, "time": get_now()})
    if output:
        print("New connection: {}:{} -> {}:{}".format(from_ip, from_port, to_ip, to_port))
        c.inc()

    # Save to file
    ips_json = json.dumps(ips)
    f = open(recorded_addrs_file, "w")
    f.write(ips_json)
    f.close()

    return ips


def block_ip_ufw(from_ip, path="/firewall/user.rules"):
    """
    Adds a block rule in UFW

    Keyword arguments:
    from_ip -- The IP to block
    path -- The path to the user.rules file
    """
    str1 = "### tuple ### deny any any 0.0.0.0/0 any {} in".format(from_ip)
    str2 = "-A ufw-user-input -s {} -j DROP".format(from_ip)
    match_string = "### RULES ###"
    insert_string = "\n{}\n{}\n".format(str1, str2)
    with open(path, 'r+') as fd:
        contents = fd.readlines()
        if match_string in contents[-1]:
            contents.append(insert_string)
        else:
            for index, line in enumerate(contents):
                if match_string in line and insert_string not in contents[index + 1]:
                    contents.insert(index + 1, insert_string)
                    break
        fd.seek(0)
        fd.writelines(contents)


def interpret_packet(pkt):
    """
    Gets the to and from IP and Port from the packet

    Keyword arguments:
    pkt -- The packet
    """
    from_ip = from_port = to_ip = to_port = ""
    if "IP" in pkt:
        from_ip = pkt["IP"].src
        to_ip = pkt["IP"].dst
    if "TCP" in pkt:
        from_port = pkt["TCP"].sport
        to_port = pkt["TCP"].dport

    return from_ip, from_port, to_ip, to_port


if __name__ == "__main__":
    start_http_server(5000)
    # sniff(filter="tcp", prn=analyze_network)
    sniff(filter="tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn", prn=analyze_network)
