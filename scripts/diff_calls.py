"""python scripts/diff_calls.py 3 4   - show which lines differ between two stored raw tool outputs."""
import sqlite3, sys, difflib
db = sqlite3.connect("data/pentest.db")
a, b = (db.execute("SELECT raw_output_untrusted FROM tool_calls WHERE id=?", (int(i),)).fetchone()[0] or "" for i in sys.argv[1:3])
for line in difflib.unified_diff(a.splitlines(), b.splitlines(), "call %s" % sys.argv[1], "call %s" % sys.argv[2], lineterm=""):
    print(line)
