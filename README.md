Description:
This project is a C++ based Firewall Simulator that allows you to define and test firewall rules interactively. It supports:

CIDR-based IP rules and single IP rules

Port ranges for flexible packet filtering

Protocol-specific rules (TCP, UDP, or ANY)

Wildcard IP rules for catch-all scenarios

First-match policy to simulate real firewall behavior

Logging of matched rule for debugging and visualization

Users can load rules from a file (rules.txt) and test packets interactively to see whether they are ALLOWED or DENIED, along with the rule that triggered the decision.

Tech Stack:

C++ (STL, File I/O, Bitwise operations)

Networking Concepts (IP, CIDR, Ports, Protocols)

Sample Rules (rules.txt):

192.168.1.0/24 80 ALLOW TCP
192.168.1.100/32 22 DENY ANY
10.0.0.0/8 1000-2000 ALLOW UDP
172.16.0.0/16 53 ALLOW TCP

Usage:

1]Compile the code: g++ firewall.cpp -o firewall

2]Run the program: ./firewall (Linux/macOS) or firewall.exe (Windows)

3]Enter packet details in the format: IP Port Protocol (e.g., 192.168.1.50 80 TCP)

4]Type exit to quit the program
* 21 DENY TCP
* 443 ALLOW TCP
* 0-65535 DENY ANY
