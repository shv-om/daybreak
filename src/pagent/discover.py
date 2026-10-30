"""Deterministic discovery: no model involved. Every call goes through the policy gateway."""
from __future__ import annotations
import os
from .parse import extract_js_signals, extract_links, parse_dir_probe, parse_http_get, parse_http_head, parse_nmap_xml, sanitize
from .policy import PolicyGateway
from .scope import Scope
from .store import Store
from .wordlist import load_wordlist

CONTENT_DISCOVERY_WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "..",
                                               "config", "content_discovery_wordlist.json")
MAX_CONTENT_DISCOVERY_REQUESTS = 200   # hard cap: (targets x prefixes x wordlist) must stay under this, or the run refuses to start


def hosts_from_scope(scope: Scope) -> list:
    """(host, port) pairs. Only named hosts and single-address CIDRs are used; wider CIDRs are NOT
    expanded here (sweeping a range needs its own explicit design and approval)."""
    hosts = set(scope.allowed_hosts)
    hosts |= {str(n.network_address) for n in scope.allowed_cidrs if n.prefixlen == n.max_prefixlen}
    return sorted(hosts - scope.excluded_hosts)


def targets_from_scope(scope: Scope) -> list:
    return [(h, p) for h in hosts_from_scope(scope) for p in sorted(scope.allowed_ports)]


def run_port_discovery(gateway: PolicyGateway, store: Store, scope: Scope, run_id: int) -> dict:
    """One nmap_tcp call per host over the scope's allowed ports. Returns {host: [open ports]};
    a host is absent from the result if its scan failed (unknown, not 'none open')."""
    open_ports: dict = {}
    for host in hosts_from_scope(scope):
        args = {"host": host, "ports": sorted(scope.allowed_ports)}
        result = gateway.execute("nmap_tcp", args, proposed_by="deterministic")
        call_id = store.record_tool_call(run_id, "nmap_tcp", args, result)
        if not result["ok"]:
            continue
        try:
            obs = parse_nmap_xml(result["untrusted_output"])
        except ValueError:
            continue
        for kind, key, value in obs:
            store.add_observation(run_id, call_id, host, kind, key, value)
        open_ports[host] = sorted(int(k.split("/")[1]) for kind, k, v in obs
                                  if kind == "port_state" and v == "open" and k.startswith("tcp/"))
    return open_ports


def run_discovery(gateway: PolicyGateway, store: Store, scope: Scope, run_id=None, open_ports=None) -> dict:
    """HTTP discovery. If open_ports is given, only those ports are probed for hosts it lists."""
    run_id = run_id or store.start_run(scope)
    allowed = denied = n_obs = 0
    for host, port in targets_from_scope(scope):
        if open_ports is not None and host in open_ports and port not in open_ports[host]:
            continue
        args = {"host": host, "port": port}
        result = gateway.execute("http_head", args, proposed_by="deterministic")
        call_id = store.record_tool_call(run_id, "http_head", args, result)
        if not result["ok"]:
            denied += 1
            continue
        allowed += 1
        for kind, key, value in parse_http_head(result["untrusted_output"]):
            store.add_observation(run_id, call_id, f"{host}:{port}", kind, key, value)
            n_obs += 1
    return {"run_id": run_id, "calls_allowed": allowed, "calls_denied": denied, "observations": n_obs}


def run_crawl(gateway: PolicyGateway, store: Store, scope: Scope, run_id=None) -> dict:
    """Fetches EXACTLY scope.crawl_seeds (nothing a fetch discovers is ever followed - see
    Scope.check_crawl_seed) across every scope target, read-only (http_get, no approval needed).
    A seed whose content-type/extension looks like JavaScript is scanned for candidate endpoints
    and credential-shaped strings (extract_js_signals); anything else is scanned for links
    (extract_links). Everything found is recorded as an observation only - see
    rules.candidates_from_crawl for how a human-reviewable Finding gets built from these, and
    neither step adds anything to scope.crawl_seeds or scope.allowed_probe_targets itself."""
    run_id = run_id or store.start_run(scope)
    allowed = denied = n_obs = 0
    for host, port in targets_from_scope(scope):
        for path in sorted(scope.crawl_seeds):
            args = {"host": host, "port": port, "path": path}
            result = gateway.execute("http_get", args, proposed_by="deterministic")
            call_id = store.record_tool_call(run_id, "http_get", args, result)
            if not result["ok"]:
                denied += 1
                continue
            allowed += 1
            asset = f"{host}:{port}{path}"
            parsed = parse_http_get(result["untrusted_output"])
            if parsed["status"] is not None:
                store.add_observation(run_id, call_id, asset, "http_status", "status", str(parsed["status"]))
                n_obs += 1
            if "javascript" in parsed["content_type"].lower() or path.lower().endswith(".js"):
                for kind, key, value in extract_js_signals(parsed["body"]):
                    store.add_observation(run_id, call_id, asset, kind, key, value)
                    n_obs += 1
                continue
            for link in extract_links(parsed["body"], host, port):
                if not link["same_host"]:
                    kind = "external_link"
                elif link["is_script"]:
                    kind = "discovered_script"
                else:
                    kind = "discovered_link"
                value = link["path"] + ("?" + "&".join(link["params"]) if link["params"] else "")
                store.add_observation(run_id, call_id, asset, kind, "link", sanitize(value, 200))
                n_obs += 1
                if link["same_host"]:
                    for p in link["params"]:
                        store.add_observation(run_id, call_id, asset, "discovered_param", link["path"], p)
                        n_obs += 1
    return {"run_id": run_id, "calls_allowed": allowed, "calls_denied": denied, "observations": n_obs}


def run_content_discovery(gateway: PolicyGateway, store: Store, scope: Scope, run_id=None,
                          wordlist_path=CONTENT_DISCOVERY_WORDLIST_PATH) -> dict:
    """GETs scope.discovery_prefixes x the small checked-in wordlist (see pagent.wordlist) across
    every scope target, read-only (dir_probe, no approval needed - see pagent.tools.dir_probe for
    why). Nothing found here is fetched further or treated as authorized for anything beyond this
    one existence check - see rules.candidates_from_discovery for how a human-reviewable Finding
    gets built, and it does not add anything to scope.crawl_seeds/allowed_probe_targets itself.
    Raises ValueError (fails closed, before sending a single request) if the combination of
    targets x prefixes x wordlist would exceed MAX_CONTENT_DISCOVERY_REQUESTS."""
    run_id = run_id or store.start_run(scope)
    wordlist = load_wordlist(wordlist_path)
    targets = targets_from_scope(scope)
    total = len(targets) * len(scope.discovery_prefixes) * len(wordlist)
    if total > MAX_CONTENT_DISCOVERY_REQUESTS:
        raise ValueError(f"content discovery would make {total} requests, over the hard cap of "
                         f"{MAX_CONTENT_DISCOVERY_REQUESTS} - narrow discovery_prefixes or run against fewer targets")
    allowed = denied = n_obs = 0
    for host, port in targets:
        for prefix in sorted(scope.discovery_prefixes):
            for candidate in wordlist:
                path = prefix + candidate
                args = {"host": host, "port": port, "path": path}
                result = gateway.execute("dir_probe", args, proposed_by="deterministic")
                call_id = store.record_tool_call(run_id, "dir_probe", args, result)
                if not result["ok"]:
                    denied += 1
                    continue
                allowed += 1
                parsed = parse_dir_probe(result["untrusted_output"])
                asset = f"{host}:{port}{path}"
                if parsed["status"] is not None:
                    store.add_observation(run_id, call_id, asset, "http_status", "status", str(parsed["status"]))
                    n_obs += 1
                if parsed["content_type"]:
                    store.add_observation(run_id, call_id, asset, "http_header", "content-type", parsed["content_type"])
                    n_obs += 1
    return {"run_id": run_id, "calls_allowed": allowed, "calls_denied": denied, "observations": n_obs}
