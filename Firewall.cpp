#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include <fstream>
#include <algorithm>

using namespace std;

// Structure to store a firewall rule
struct Rule {
    uint32_t ip;
    uint32_t mask;
    int portStart;
    int portEnd;
    string action;     // ALLOW or DENY
    string protocol;   // TCP, UDP, ANY
    string originalRule;
    bool isWildcard;   // true if IP is *
};

// Convert IP string to integer
uint32_t ipToInt(const string &ipStr) {
    if (ipStr == "*") return 0; // wildcard handling
    stringstream ss(ipStr);
    string token;
    uint32_t ip = 0;
    for (int i = 0; i < 4; i++) {
        getline(ss, token, '.');
        ip = (ip << 8) + stoi(token);
    }
    return ip;
}

// Parse CIDR notation into IP and mask
void parseCIDR(const string &cidr, uint32_t &ip, uint32_t &mask, bool &isWildcard) {
    if (cidr == "*") {
        ip = 0;
        mask = 0;
        isWildcard = true;
        return;
    }
    size_t pos = cidr.find('/');
    string ipStr = cidr.substr(0, pos);
    int prefix = stoi(cidr.substr(pos + 1));
    ip = ipToInt(ipStr);
    mask = prefix == 0 ? 0 : (~0u << (32 - prefix));
    isWildcard = false;
}

// Parse port range string (e.g., "80" or "1000-2000")
void parsePortRange(const string &portStr, int &start, int &end) {
    size_t pos = portStr.find('-');
    if (pos == string::npos) {
        start = end = stoi(portStr);
    } else {
        start = stoi(portStr.substr(0, pos));
        end = stoi(portStr.substr(pos + 1));
    }
}

// Check if a packet matches a rule
bool matches(const Rule &rule, uint32_t ip, int port, const string &proto) {
    bool ipMatch = rule.isWildcard || ((ip & rule.mask) == (rule.ip & rule.mask));
    bool portMatch = port >= rule.portStart && port <= rule.portEnd;
    bool protoMatch = (rule.protocol == "ANY" || rule.protocol == proto);
    return ipMatch && portMatch && protoMatch;
}

int main() {
    vector<Rule> rules;
    ifstream file("rules.txt");
    if (!file.is_open()) {
        cerr << "Error: Could not open rules.txt" << endl;
        return 1;
    }

    string line;
    while (getline(file, line)) {
        if (line.empty()) continue;
        stringstream ss(line);
        string cidr, portStr, action, protocol;
        ss >> cidr >> portStr >> action >> protocol;
        Rule rule;
        parseCIDR(cidr, rule.ip, rule.mask, rule.isWildcard);
        parsePortRange(portStr, rule.portStart, rule.portEnd);
        rule.action = action;
        rule.protocol = protocol;
        rule.originalRule = line;
        rules.push_back(rule);
    }
    file.close();

    cout << "Firewall rules loaded. Enter packets to test (IP port protocol), type 'exit' to quit:\n";

    while (true) {
        string ipStr, proto;
        int port;
        cout << "Packet: ";
        cin >> ipStr;
        if (ipStr == "exit") break;
        cin >> port >> proto;

        transform(proto.begin(), proto.end(), proto.begin(), ::toupper);

        uint32_t ip = ipToInt(ipStr);
        string decision = "NO MATCH";
        string matchedRule = "None";

        for (auto &rule : rules) {
            if (matches(rule, ip, port, proto)) {
                decision = rule.action;
                matchedRule = rule.originalRule;
                break; // first-match policy
            }
        }

        cout << "Decision: " << decision << endl;
        cout << "Matched Rule: " << matchedRule << "\n\n";
    }

    return 0;
}
