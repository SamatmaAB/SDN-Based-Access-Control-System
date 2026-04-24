#!/usr/bin/env python3
"""Verify whitelist-based reachability in Mininet."""

from __future__ import annotations

import argparse
import sys

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch

from sdn_acl.policy import AccessPolicy
from sdn_acl.runtime import dump_flows, install_rules, verify_dump_contains_rules
from topology import ACLTopology


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify SDN ACL policy.")
    parser.add_argument("--config", default="config/whitelist.json")
    return parser.parse_args()


def ping(source, destination) -> bool:
    result = source.cmd(f"ping -c 1 -W 1 {destination.IP()}")
    return ", 0% packet loss" in result or " 0% packet loss" in result


def main() -> int:
    args = parse_args()
    policy = AccessPolicy.from_file(args.config)
    net = Mininet(
        topo=ACLTopology(policy=policy),
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=False,
        autoStaticArp=True,
    )
    net.start()
    try:
        install_rules(policy)
        flow_dump = dump_flows(policy.switch_name)
        expected_matches = [
            f"dl_src={policy.hosts[src].mac},dl_dst={policy.hosts[dst].mac}"
            for src, dst in sorted(policy.whitelist)
        ]
        missing_rules = verify_dump_contains_rules(flow_dump, expected_matches)
        failures: list[str] = []
        if missing_rules:
            failures.extend(f"Missing flow dump match: {match}" for match in missing_rules)

        for src_name, dst_name, should_pass in policy.expected_connectivity():
            src = net.get(src_name)
            dst = net.get(dst_name)
            actual = ping(src, dst)
            if actual != should_pass:
                verdict = "allowed" if should_pass else "blocked"
                failures.append(f"{src_name} -> {dst_name} expected {verdict} but observed {'allowed' if actual else 'blocked'}")

        if failures:
            print("Verification failed:")
            for failure in failures:
                print(f"- {failure}")
            return 1

        print("Verification passed. Access control matches the whitelist policy.")
        return 0
    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("warning")
    sys.exit(main())
