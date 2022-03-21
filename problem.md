## Level 1:

### Description
Write a program that reads `/proc/net/tcp` every 10 seconds, and reports any new connections.

Sample Output:
```
2021-04-28 15:28:05: New connection: 192.0.2.56:5973 -> 10.0.0.5:80
2021-04-28 15:28:05: New connection: 203.0.113.105:31313 -> 10.0.0.5:80
2021-04-28 15:28:15: New connection: 203.0.113.94:9208 -> 10.0.0.5:80
2021-04-28 15:28:15: New connection: 198.51.100.245:14201 -> 10.0.0.5:80
```

Include a readme with the program that explains any dependencies and how to build and execute the program. The interview panel will build and test the program.

## Level 2:
Implement all of the level 1 requirements plus:
1. Add a Makefile or your preferred build scripting to build and test the solution.
2. Add some tests, test for corner cases or unexpected behaviour.
3. Add the ability to detect a port scan, where a single source IP connects to more than 3 host ports in the previous minute.

Sample Output:
```
2021-04-28 15:28:05: Port scan detected: 192.0.2.56 -> 10.0.0.5 on ports 80,81,82,83
```

## Level 3:
Implement all of the level 2 requirements plus:
1. Add a prometheus endpoint to report metrics on the following:
    1. Counter - number of new connections

    Tip: There are client libraries available in many languages for providing prometheus metrics, see https://prometheus.io/docs/instrumenting/clientlibs/
2. Build the project into a docker container, provide instructions on how to execute as a container while reporting connections on the host.
3. When a port scan is detected, configure the host firewall to block connections by source-ip.

## Level 4:
Implement all of the level 3 requirements but instead of polling `/proc/net/tcp` or the host for a list of connections it's tracking, we want to use a better model and track connection attempts in real time. Use one of the following methods to track attempted connections:
1. Use a pcap library to track TCP SYN Packets
    1. Make sure the capture has a filter set to limit the number of packets passed to userspace to only interesting packets required for connection tracking.
2. Load a BPF program into the linux express data path (XDP) and attach to an interface to monitor for new connections and report to userspace.
3. Load a BPF program as a Linux Security Module (LSM) and report on new connections to userspace.

Note: Reading `/proc/net/tcp` is no longer required, and should not be implemented.
