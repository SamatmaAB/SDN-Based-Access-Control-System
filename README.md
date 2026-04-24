# SDN-Based Access Control System

This project implements whitelist-based host-to-host access control in a Mininet network using Open vSwitch and OpenFlow 1.3. Only approved source and destination pairs receive forwarding rules. All other traffic is denied by a default drop rule.

## Overview

- Enforces communication policy from `config/whitelist.json`
- Builds a single-switch Mininet topology with hosts `h1` through `h4`
- Installs OpenFlow rules directly on the switch without a remote controller
- Verifies both installed flows and end-to-end connectivity
- Includes unit tests for policy validation and rule generation

## How It Works

The policy file defines:

- the switch name
- each host's IP, MAC address, and switch port
- directional whitelist entries such as `["h1", "h2"]`

For every allowed pair, the system installs:

- one ARP forwarding rule
- one IPv4 forwarding rule

It also installs a default low-priority drop rule so unmatched traffic is blocked.

## Repository Layout

- `config/whitelist.json`: whitelist policy and host inventory
- `sdn_acl/policy.py`: policy loading, validation, connectivity expectations, flow generation
- `sdn_acl/runtime.py`: Open vSwitch command helpers for install and verification
- `topology.py`: Mininet topology launcher
- `verify_access.py`: live verification for flows and reachability
- `tests/test_policy.py`: unit tests for policy behavior
- `demo.sh`: quick end-to-end demo script
- `report/report.md`: report-ready write-up

## Requirements

Run this project in a Linux environment with:

- Python 3
- Mininet
- Open vSwitch
- `ovs-ofctl`
- `sudo` access for Mininet and OVS commands

Typical usage assumes Mininet and OVS are already installed and working.

## Policy Configuration

The whitelist is stored in `config/whitelist.json`.

Example:

```json
{
  "switch": "s1",
  "hosts": [
    { "name": "h1", "ip": "10.0.0.1/24", "mac": "00:00:00:00:00:01", "port": 1 },
    { "name": "h2", "ip": "10.0.0.2/24", "mac": "00:00:00:00:00:02", "port": 2 },
    { "name": "h3", "ip": "10.0.0.3/24", "mac": "00:00:00:00:00:03", "port": 3 },
    { "name": "h4", "ip": "10.0.0.4/24", "mac": "00:00:00:00:00:04", "port": 4 }
  ],
  "whitelist": [
    ["h1", "h2"],
    ["h2", "h1"],
    ["h1", "h3"],
    ["h3", "h1"]
  ]
}
```

## Important Policy Behavior

Whitelist entries are directional.

- `["h1", "h2"]` allows traffic from `h1` to `h2`
- `["h2", "h1"]` allows traffic from `h2` to `h1`

For successful `ping` verification, both directions must be present. ICMP echo requires the request path and the reply path, so a one-way whitelist entry is not enough for end-to-end reachability.

With the sample policy:

- `h1 <-> h2` is allowed
- `h1 <-> h3` is allowed
- any communication involving `h4` is blocked
- `h2 <-> h3` is blocked

## Running the Project

Run unit tests:

```bash
python3 -m unittest discover -s tests -v
```

Start the Mininet topology with an interactive CLI:

```bash
sudo python3 topology.py
```

Start the topology, install rules, and exit:

```bash
sudo python3 topology.py --no-cli
```

Run live verification:

```bash
sudo python3 verify_access.py
```

Run the full demo script:

```bash
chmod +x demo.sh
./demo.sh
```

## Manual Validation in Mininet

After launching `topology.py`, test reachability from the Mininet CLI:

```bash
h1 ping -c 1 h2
h1 ping -c 1 h3
h1 ping -c 1 h4
h2 ping -c 1 h3
```

Expected results:

- `h1 -> h2`: reachable
- `h1 -> h3`: reachable
- `h1 -> h4`: blocked
- `h2 -> h3`: blocked

Inspect installed switch rules with:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

## Verification Strategy

`verify_access.py` checks two things:

1. Expected flow matches appear in the switch flow dump.
2. Actual host-to-host connectivity matches the whitelist policy.

If verification fails, the script prints each mismatch and exits with a non-zero status.

## Notes

- The topology uses one Open vSwitch bridge in secure fail mode.
- Rules are installed directly on the switch, so no external controller is required.
- Only ARP and IPv4 traffic for approved host pairs is forwarded.
- Unmatched traffic is dropped by the default rule.

## Report

Submission material is available in `report/report.md`. Supporting notes for report assets are in `report/README.md`.
