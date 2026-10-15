"""Tests for change_detector.diff using simulated changes to the real baseline snapshot (nothing is changed in Azure)."""
import copy
import glob
import json
import os
import unittest

from change_detector import diff

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = json.load(open(sorted(glob.glob(os.path.join(HERE, "snapshots", "*.json")))[0]))


def sev(changes, text):
    return next(c["severity"] for c in changes if text in c["detail"])


class TestChangeDetection(unittest.TestCase):
    def test_no_change(self):
        self.assertEqual(diff(BASE, copy.deepcopy(BASE)), [])

    def test_internet_rdp_rule_is_high(self):
        new = copy.deepcopy(BASE)
        new["nsg_rules"]["HVMC-Web-NSG/Allow-RDP"] = "Inbound Allow TCP * -> 3389 p110"
        self.assertEqual(sev(diff(BASE, new), "Allow-RDP"), "High")

    def test_new_global_admin_is_critical(self):
        new = copy.deepcopy(BASE)
        new["directory_roles"]["Global Administrator"] = new["directory_roles"]["Global Administrator"] + ["mallory@example.com"]
        self.assertEqual(sev(diff(BASE, new), "mallory"), "Critical")

    def test_storage_hardening_is_info_but_weakening_is_high(self):
        better, worse = copy.deepcopy(BASE), copy.deepcopy(BASE)
        better["storage_security"]["publicNetworkAccess"] = "Disabled"
        worse["storage_security"]["minimumTlsVersion"] = "TLS1_0"
        self.assertEqual(sev(diff(BASE, better), "publicNetworkAccess"), "Info")
        self.assertEqual(sev(diff(BASE, worse), "minimumTlsVersion"), "High")

    def test_new_public_ip_is_high(self):
        new = copy.deepcopy(BASE)
        new["public_ips"].append("Unexpected-PIP|20.1.2.3")
        self.assertEqual(sev(diff(BASE, new), "Unexpected-PIP"), "High")

    def test_owner_assignment_is_high_and_user_is_low(self):
        new = copy.deepcopy(BASE)
        new["role_assignments"].append("new.admin@example.com|Owner|c3640794")
        new["users"].append("new.hire@sabithaskaranavargmail.onmicrosoft.com")
        ch = diff(BASE, new)
        self.assertEqual(sev(ch, "new.admin"), "High")
        self.assertEqual(sev(ch, "new.hire"), "Low")

    def test_group_membership_and_removed_resource(self):
        new = copy.deepcopy(BASE)
        g = next(iter(new["group_members"]))
        new["group_members"][g] = new["group_members"][g] + ["Carlos Diaz"]
        new["resources"] = new["resources"][1:]
        ch = diff(BASE, new)
        self.assertEqual(sev(ch, "Carlos Diaz"), "Medium")
        self.assertTrue(any(c["kind"] == "removed" and c["category"] == "resources" for c in ch))

    def test_every_change_names_risks_and_procedure(self):
        new = copy.deepcopy(BASE)
        new["public_ips"].append("X|1.1.1.1")
        for c in diff(BASE, new):
            self.assertTrue(c["reassess"] and c["procedure"].startswith("IP-"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
