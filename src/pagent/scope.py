"""Machine-readable authorization scope. Deterministic; no model involvement."""
from __future__ import annotations
import ipaddress, json
from dataclasses import dataclass
from datetime import datetime, timezone


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class Scope:
    engagement_id: str
    authorized_by: str
    valid_from: datetime
    valid_until: datetime
    allowed_hosts: frozenset
    allowed_cidrs: tuple
    excluded_hosts: frozenset
    allowed_ports: frozenset
    allowed_tools: frozenset
    intrusive_allowed: bool = False
    allowed_probe_targets: tuple = ()
    crawl_seeds: tuple = ()    # explicit paths the (read-only) crawler may fetch - see pagent.crawl
    discovery_prefixes: tuple = ()   # explicit path prefixes content discovery may enumerate under - see pagent.discover.run_content_discovery

    @classmethod
    def from_dict(cls, d: dict) -> "Scope":
        try:
            s = cls(
                engagement_id=str(d["engagement_id"]),
                authorized_by=str(d["authorized_by"]),
                valid_from=datetime.fromisoformat(d["valid_from"]),
                valid_until=datetime.fromisoformat(d["valid_until"]),
                allowed_hosts=frozenset(h.lower() for h in d.get("allowed_hosts", [])),
                allowed_cidrs=tuple(ipaddress.ip_network(c) for c in d.get("allowed_cidrs", [])),
                excluded_hosts=frozenset(h.lower() for h in d.get("excluded_hosts", [])),
                allowed_ports=frozenset(int(p) for p in d.get("allowed_ports", [])),
                allowed_tools=frozenset(d.get("allowed_tools", [])),
                intrusive_allowed=bool(d.get("intrusive_allowed", False)),
                allowed_probe_targets=tuple(sorted({(t["path"], t["param"]) for t in d.get("allowed_probe_targets", [])})),
                crawl_seeds=tuple(sorted({str(p) for p in d.get("crawl_seeds", [])})),
                discovery_prefixes=tuple(sorted({str(p) for p in d.get("discovery_prefixes", [])})),
            )
        except (KeyError, TypeError, ValueError) as e:
            raise ScopeError(f"invalid scope file: {e}") from e
        if any(not p.startswith("/") for p in s.crawl_seeds):
            raise ScopeError("crawl_seeds entries must be paths starting with '/'")
        if any(not (p.startswith("/") and p.endswith("/")) for p in s.discovery_prefixes):
            raise ScopeError("discovery_prefixes entries must be paths starting and ending with '/' (e.g. '/', '/rest/')")
        if s.valid_from.tzinfo is None or s.valid_until.tzinfo is None:
            raise ScopeError("scope timestamps must include a timezone")
        if s.valid_until <= s.valid_from:
            raise ScopeError("valid_until must be after valid_from")
        if not (s.allowed_hosts or s.allowed_cidrs):
            raise ScopeError("scope must allow at least one host or CIDR")
        if not s.allowed_ports:
            raise ScopeError("scope must list allowed ports")
        return s

    @classmethod
    def load(cls, path: str) -> "Scope":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def check_probe_target(self, path: str, param: str) -> bool:
        """Explicit opt-in only: a path+param must be named here before any active probe may touch it."""
        return (path, param) in self.allowed_probe_targets

    def check_crawl_seed(self, path: str) -> bool:
        """Explicit opt-in only, same discipline as check_probe_target: the (read-only) crawler
        may fetch ONLY a path named here - never a path it discovered on a previous fetch. A
        discovered link is surfaced as a candidate for a human to add here next time, not followed
        automatically (see pagent.crawl)."""
        return path in self.crawl_seeds

    def check_discovery_path(self, path: str) -> bool:
        """Explicit opt-in only, same discipline as check_crawl_seed: content discovery
        (pagent.tools.dir_probe) may request a path ONLY if it starts with a prefix named here.
        This only authorizes the PREFIX; which candidate segment may follow it is bounded, by
        construction, to the small fixed wordlist pagent.discover.run_content_discovery iterates
        over - this method does not and cannot know about that list, the same way
        check_probe_target does not know which literal bytes sqli_probe sends."""
        return any(path.startswith(p) for p in self.discovery_prefixes)

    def check_target(self, host: str, port: int, now: datetime | None = None):
        """Return (allowed, reason). Default deny."""
        now = now or datetime.now(timezone.utc)
        if not (self.valid_from <= now <= self.valid_until):
            return False, "outside authorization window"
        host = host.strip().lower()
        if host in self.excluded_hosts:
            return False, "host explicitly excluded"
        if port not in self.allowed_ports:
            return False, f"port {port} not in scope"
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            if host in self.allowed_hosts:
                return True, "ip literal allowlisted"
            if any(ip in net for net in self.allowed_cidrs):
                return True, "ip in allowed CIDR"
            return False, "ip not in any allowed CIDR or allowed_hosts"
        if host in self.allowed_hosts:
            return True, "hostname allowlisted"
        return False, "hostname not allowlisted"
