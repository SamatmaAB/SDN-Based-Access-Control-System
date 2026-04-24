# SDN-Based Access Control System

## Abstract

This project implements an SDN-based access control system in Mininet using Open vSwitch and OpenFlow 1.3 rules. A whitelist defines which hosts are allowed to communicate. The system installs forwarding rules only for authorized source-destination pairs and drops all other traffic by default. This approach demonstrates centralized policy-driven access control without relying on a traditional distributed firewall configuration on each host.

## Problem Statement

The goal is to allow only authorized hosts to communicate within the network. The system must:

- maintain a whitelist of approved hosts and communication pairs
- install allow and deny rules
- block unauthorized access
- verify access control behavior
- perform regression testing to ensure policy consistency

## Objectives

- Build a simple SDN topology in Mininet
- Represent access policy in a configurable whitelist file
- Translate the policy into OpenFlow rules on the switch
- Permit only authorized traffic
- Deny all unauthorized communication by default
- Verify both policy correctness and live network behavior

## Tools and Technologies

- Python 3
- Mininet
- Open vSwitch
- OpenFlow 1.3
- `ovs-ofctl` and `ovs-vsctl`
- `unittest`

## System Design

The network uses a single Open vSwitch bridge `s1` connected to four hosts: `h1`, `h2`, `h3`, and `h4`.

The access policy is defined in `config/whitelist.json`. Each whitelist entry is directional. For example, if `["h1", "h2"]` exists, traffic from `h1` to `h2` is allowed. For full bidirectional communication, both directions must be present.

The switch runs in `secure` fail mode. This is important because it prevents the switch from forwarding packets normally when no matching rule exists.

## Implementation

### 1. Policy Engine

The file `sdn_acl/policy.py`:

- loads the whitelist configuration
- validates host definitions and switch ports
- detects invalid whitelist entries
- builds the expected connectivity matrix
- generates OpenFlow allow rules for ARP and IPv4 traffic
- adds a default drop rule

### 2. Topology Setup

The file `topology.py`:

- builds the Mininet topology
- creates one Open vSwitch switch
- attaches hosts to fixed switch ports
- installs whitelist-based flow rules

### 3. Verification

The file `verify_access.py`:

- starts the topology
- installs flow rules
- checks whether required flow entries were installed
- runs host-to-host ping checks
- compares observed connectivity with the expected policy

### 4. Regression Tests

The file `tests/test_policy.py` verifies:

- whitelist matrix correctness
- reverse-policy consistency detection
- duplicate port rejection
- unknown host rejection
- default drop flow generation
- missing flow detection in switch dumps

## Whitelist Policy Used

The sample policy allows:

- `h1 <-> h2`
- `h1 <-> h3`

The following are blocked:

- `h2 <-> h3`
- any communication involving `h4`

## Commands Used

### Run regression tests

```bash
python3 -m unittest discover -s tests -v
```

### Run live verification

```bash
sudo python3 verify_access.py
```

### Run the full demo

```bash
chmod +x demo.sh
./demo.sh
```

### Launch interactive topology

```bash
sudo python3 topology.py
```

## Expected Results

Successful communication:

- `h1` to `h2`
- `h2` to `h1`
- `h1` to `h3`
- `h3` to `h1`

Blocked communication:

- `h2` to `h3`
- `h3` to `h2`
- `h1` to `h4`
- `h4` to any host

Expected verification output:

```text
Verification passed. Access control matches the whitelist policy.
```

## Sample Observation Table

| Source | Destination | Expected Result |
|--------|-------------|-----------------|
| h1     | h2          | Allowed         |
| h2     | h1          | Allowed         |
| h1     | h3          | Allowed         |
| h3     | h1          | Allowed         |
| h2     | h3          | Blocked         |
| h3     | h2          | Blocked         |
| h1     | h4          | Blocked         |
| h4     | h1          | Blocked         |

## Advantages

- centralized access policy
- simple whitelist management
- clear separation between policy and enforcement
- easy verification and regression testing

## Limitations

- current implementation uses a single-switch topology
- the sample policy is static and file-based
- verification depends on Mininet and Open vSwitch being available locally

## Conclusion

The project successfully demonstrates SDN-based access control using whitelist-driven OpenFlow rule installation. Authorized communication is permitted, unauthorized communication is denied, and the policy can be validated through automated tests and live Mininet verification. This shows how SDN can simplify access control management by moving policy enforcement into the network data plane.
