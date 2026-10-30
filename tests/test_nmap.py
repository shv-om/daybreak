import os, tempfile, unittest
from pagent.audit import AuditLog
from pagent.discover import run_discovery, run_port_discovery
from pagent.parse import parse_nmap_xml
from pagent.policy import PolicyGateway
from pagent.report import build_report, to_markdown
from pagent.rules import open_port_findings
from pagent.store import Store
from pagent.tools.http_head import make_http_head
from pagent.tools.nmap_tcp import build_command, make_nmap_tcp
from test_discovery import scope_for

# SYNTHETIC sample shaped like nmap -oX output; not captured from a real scan.
XML = """<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><ports>
<port protocol="tcp" portid="5000"><state state="open"/><service name="upnp"/></port>
<port protocol="tcp" portid="8080"><state state="closed"/></port>
</ports></host></nmaprun>"""


def gw_for(scope, runner, http=None, path="/usr/bin/nmap"):
    tools = {"nmap_tcp": make_nmap_tcp(runner, path),
             "http_head": make_http_head(http or (lambda h, p, t: (200, {})))}
    return PolicyGateway(scope, tools, AuditLog(os.path.join(tempfile.mkdtemp(), "a.jsonl")))


def scope_ports(ports, **kw):
    return scope_for(ports[0], allowed_ports=ports, allowed_hosts=["localhost"], allowed_cidrs=[],
                     allowed_tools=["http_head", "nmap_tcp"], **kw)


class ParseTests(unittest.TestCase):
    def test_parse(self):
        obs = parse_nmap_xml(XML)
        self.assertIn(("port_state", "tcp/5000", "open"), obs)
        self.assertIn(("port_service_guess", "tcp/5000", "upnp"), obs)
        self.assertIn(("port_state", "tcp/8080", "closed"), obs)

    def test_rejects_entities_and_garbage(self):
        with self.assertRaises(ValueError):
            parse_nmap_xml('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>')
        with self.assertRaises(ValueError):
            parse_nmap_xml("not xml")

    def test_skips_odd_values(self):
        x = '<nmaprun><port protocol="icmp" portid="1"><state state="open"/></port><port protocol="tcp" portid="x"><state state="open"/></port><port protocol="tcp" portid="9"><state state="weird"/></port></nmaprun>'
        self.assertEqual(parse_nmap_xml(x), [])


class AdapterTests(unittest.TestCase):
    def test_command_is_fixed_and_safe(self):
        cmd = build_command("nmap", "localhost", [8080, 80])
        self.assertEqual(cmd[-1], "localhost")
        self.assertIn("80,8080", cmd)
        for forbidden in ("--script", "-sV", "-O", "-A", "-sS", "-sU", "-T5"):
            self.assertNotIn(forbidden, cmd)

    def test_gateway_denials(self):
        sc = scope_ports([80, 443, 5000])
        gw = gw_for(sc, lambda c, t: XML)
        bad = [{"host": "localhost", "ports": [22]}, {"host": "localhost", "ports": []},
               {"host": "localhost", "ports": [80, 80]}, {"host": "localhost", "ports": ["80"]},
               {"host": "-oN", "ports": [80]}, {"host": "8.8.8.8", "ports": [80]},
               {"host": "localhost", "ports": list(range(1, 30))}, {"host": "localhost"}]
        for args in bad:
            self.assertFalse(gw.execute("nmap_tcp", args)["ok"], args)
        self.assertTrue(gw.execute("nmap_tcp", {"host": "localhost", "ports": [80, 5000]})["ok"])

    def test_missing_nmap_fails_closed(self):
        sc = scope_ports([5000])
        gw = gw_for(sc, lambda c, t: XML, path="")
        r = gw.execute("nmap_tcp", {"host": "localhost", "ports": [5000]})
        self.assertFalse(r["ok"])


class FlowTests(unittest.TestCase):
    def test_only_open_ports_are_probed_and_reported(self):
        sc = scope_ports([80, 443, 5000, 8080])
        seen = []
        def http(h, p, t):
            seen.append(p); return 200, {"X-Frame-Options": "DENY"}
        gw = gw_for(sc, lambda c, t: XML, http)
        st = Store(":memory:")
        rid = st.start_run(sc)
        op = run_port_discovery(gw, st, sc, rid)
        self.assertEqual(op, {"localhost": [5000]})
        run_discovery(gw, st, sc, run_id=rid, open_ports=op)
        self.assertEqual(seen, [5000])
        fs = open_port_findings(st, rid)
        self.assertEqual(len(fs), 1)
        self.assertEqual((fs[0].status, fs[0].asset), ("informational", "localhost:5000"))
        rep = build_report(rid, sc, fs)
        self.assertEqual(rep["summary"]["informational"], 1)
        self.assertIn(fs[0].id, to_markdown(rep))

    def test_failed_scan_falls_back_to_all_scope_ports(self):
        sc = scope_ports([80, 5000])
        seen = []
        def boom(c, t): raise TimeoutError()
        gw = gw_for(sc, boom, lambda h, p, t: (seen.append(p) or (200, {})))
        st = Store(":memory:")
        rid = st.start_run(sc)
        op = run_port_discovery(gw, st, sc, rid)
        self.assertEqual(op, {})
        run_discovery(gw, st, sc, run_id=rid, open_ports=op)
        self.assertEqual(sorted(seen), [80, 5000])


if __name__ == "__main__":
    unittest.main()
