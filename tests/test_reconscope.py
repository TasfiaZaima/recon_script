import json, tempfile, unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from reconscope import Scope

class ScopeTests(unittest.TestCase):
    def test_exclusion_wins_over_wildcard(self):
        s=Scope({"in_scope":["*.example.com"],"out_of_scope":["admin.example.com"]})
        self.assertTrue(s.allowed("api.example.com")); self.assertFalse(s.allowed("admin.example.com")); self.assertFalse(s.allowed("other.test"))
    def test_exact(self):
        s=Scope({"in_scope":["example.com"]}); self.assertTrue(s.allowed("example.com.")); self.assertFalse(s.allowed("www.example.com"))
if __name__ == "__main__": unittest.main()
