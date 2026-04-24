"""Mininet/Open vSwitch runtime helpers."""

from __future__ import annotations

import subprocess
from typing import Iterable

from sdn_acl.policy import AccessPolicy


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def install_rules(policy: AccessPolicy) -> None:
    switch = policy.switch_name
    run_command(["ovs-ofctl", "-O", "OpenFlow13", "del-flows", switch])
    for rule in policy.build_flow_rules():
        run_command(
            [
                "ovs-ofctl",
                "-O",
                "OpenFlow13",
                "add-flow",
                switch,
                rule.as_ovs_rule(),
            ]
        )


def dump_flows(switch: str) -> str:
    result = run_command(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch])
    return result.stdout


def verify_dump_contains_rules(flow_dump: str, expected_matches: Iterable[str]) -> list[str]:
    missing: list[str] = []
    for expected in expected_matches:
        if expected not in flow_dump:
            missing.append(expected)
    return missing
