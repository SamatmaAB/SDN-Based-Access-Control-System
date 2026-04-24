"""Whitelist-backed access-control policy helpers."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    mac: str
    port: int

    @property
    def ipv4(self) -> str:
        return self.ip.split("/", 1)[0]


@dataclass(frozen=True)
class FlowRule:
    priority: int
    match: str
    actions: str

    def as_ovs_rule(self) -> str:
        if self.match:
            return f"priority={self.priority},{self.match},actions={self.actions}"
        return f"priority={self.priority},actions={self.actions}"


class PolicyError(ValueError):
    """Raised when the whitelist policy is invalid."""


class AccessPolicy:
    def __init__(self, switch_name: str, hosts: dict[str, Host], whitelist: set[tuple[str, str]]):
        self.switch_name = switch_name
        self.hosts = hosts
        self.whitelist = whitelist

    @classmethod
    def from_file(cls, path: str | Path) -> "AccessPolicy":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        hosts = {
            entry["name"]: Host(
                name=entry["name"],
                ip=entry["ip"],
                mac=entry["mac"].lower(),
                port=int(entry["port"]),
            )
            for entry in raw["hosts"]
        }
        whitelist = {tuple(pair) for pair in raw["whitelist"]}
        policy = cls(raw["switch"], hosts, whitelist)
        policy.validate()
        return policy

    def validate(self) -> None:
        if not self.hosts:
            raise PolicyError("At least one host must be defined.")

        ports_seen: set[int] = set()
        macs_seen: set[str] = set()
        for host in self.hosts.values():
            if host.port in ports_seen:
                raise PolicyError(f"Duplicate switch port detected: {host.port}")
            if host.mac in macs_seen:
                raise PolicyError(f"Duplicate MAC detected: {host.mac}")
            ports_seen.add(host.port)
            macs_seen.add(host.mac)

        for src, dst in self.whitelist:
            if src not in self.hosts or dst not in self.hosts:
                raise PolicyError(f"Whitelist entry ({src}, {dst}) references an unknown host.")
            if src == dst:
                raise PolicyError(f"Whitelist entry ({src}, {dst}) is a self-reference.")

    def allowed(self, src: str, dst: str) -> bool:
        return (src, dst) in self.whitelist

    def matrix(self) -> dict[str, dict[str, bool]]:
        return {
            src: {dst: self.allowed(src, dst) for dst in self.hosts}
            for src in self.hosts
        }

    def missing_reverse_rules(self) -> list[tuple[str, str]]:
        missing: list[tuple[str, str]] = []
        for src, dst in sorted(self.whitelist):
            if (dst, src) not in self.whitelist:
                missing.append((src, dst))
        return missing

    def build_flow_rules(self) -> list[FlowRule]:
        rules: list[FlowRule] = [
            FlowRule(priority=0, match="", actions="drop"),
        ]
        for src_name, dst_name in sorted(self.whitelist):
            src = self.hosts[src_name]
            dst = self.hosts[dst_name]
            rules.extend(self._pair_rules(src, dst))
        return rules

    def expected_connectivity(self) -> list[tuple[str, str, bool]]:
        pairs: list[tuple[str, str, bool]] = []
        for src in sorted(self.hosts):
            for dst in sorted(self.hosts):
                if src == dst:
                    continue
                pairs.append((src, dst, self.allowed(src, dst) and self.allowed(dst, src)))
        return pairs

    def _pair_rules(self, src: Host, dst: Host) -> Iterable[FlowRule]:
        # Allow ARP and IPv4 only for explicitly approved source-destination pairs.
        return (
            FlowRule(
                priority=200,
                match=f"in_port={src.port},dl_src={src.mac},dl_dst={dst.mac},arp",
                actions=f"output:{dst.port}",
            ),
            FlowRule(
                priority=200,
                match=f"in_port={src.port},dl_src={src.mac},dl_dst={dst.mac},ip",
                actions=f"output:{dst.port}",
            ),
        )
