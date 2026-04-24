#!/usr/bin/env python3
"""Launch a Mininet topology and apply whitelist-based ACL rules."""

from __future__ import annotations

import argparse

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo

from sdn_acl.policy import AccessPolicy
from sdn_acl.runtime import install_rules


class ACLTopology(Topo):
    def build(self, policy: AccessPolicy) -> None:
        switch = self.addSwitch(policy.switch_name, protocols="OpenFlow13", failMode="secure")
        for host in sorted(policy.hosts.values(), key=lambda item: item.port):
            host_name = self.addHost(host.name, ip=host.ip, mac=host.mac)
            self.addLink(host_name, switch, port2=host.port)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Launch SDN ACL topology.")
    parser.add_argument(
        "--config",
        default="config/whitelist.json",
        help="Path to whitelist configuration JSON.",
    )
    parser.add_argument(
        "--no-cli",
        action="store_true",
        help="Start the topology, install rules, and exit.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    policy = AccessPolicy.from_file(args.config)
    topo = ACLTopology(policy=policy)
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch, autoSetMacs=False, autoStaticArp=True)
    net.start()
    try:
        install_rules(policy)
        print(f"Installed {len(policy.build_flow_rules())} flow rules on {policy.switch_name}.")
        if not args.no_cli:
            CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()
