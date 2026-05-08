"""
[TST-01-EC2] Tests unitarios para ec2_analyzer.
"""
import sys
sys.path.insert(0, '.')

import pytest
from tests.conftest import make_collector_output, assert_finding, assert_no_finding, ACCOUNT_ID, REGION
from analyzers import ec2_analyzer


def _base_raw() -> dict:
    return {
        "ebs_encryption_by_default": True,
        "instances":       {},
        "security_groups": {},
        "vpcs":            {},
        "ebs_volumes":     {},
        "ebs_snapshots":   {},
        "amis":            {},
        "subnets":         {},
        "network_acls":    {},
        "elastic_ips":     [],
        "missing_critical_endpoints": [],
        "summary":         {},
    }


def _instance(iid: str, **kwargs) -> dict:
    defaults = {
        "state":              "running",
        "public_ip":          None,
        "imdsv2_required":    True,
        "imdsv2_enforced":    True,
        "monitoring":         "enabled",
        "monitoring_enabled": True,
        "ssm_managed":        True,
        "exposure_type":      "private",
        "behind_elb":         False,
        "directly_exposed":   False,
    }
    defaults.update(kwargs)
    return defaults


def _sg(sgid: str, **kwargs) -> dict:
    defaults = {
        "name":                 "test-sg",
        "is_default":           False,
        "inbound_rules":        [],
        "outbound_rules":       [],
        "open_to_world":        False,
        "exposed_port_details": [],
    }
    defaults.update(kwargs)
    return defaults


# ── CIS-EC2-2.2.1 EBS encryption by default ──────────────────────────────────

class TestEBSEncryptionByDefault:

    def test_fail_when_disabled(self):
        raw = _base_raw()
        raw["ebs_encryption_by_default"] = False
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-2.2.1", "FAIL")

    def test_pass_when_enabled(self):
        raw    = _base_raw()
        output = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-2.2.1", "PASS")


# ── CIS-EC2-2.2.1-VOL EBS volumes encrypted ──────────────────────────────────

class TestEBSVolumesEncrypted:

    def test_fail_when_volume_unencrypted(self):
        raw = _base_raw()
        raw["ebs_volumes"] = {
            "vol-001": {"encrypted": False, "kms_key_id": None, "state": "in-use", "attachments": []}
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-2.2.1-VOL", "FAIL")

    def test_pass_when_volume_encrypted(self):
        raw = _base_raw()
        raw["ebs_volumes"] = {
            "vol-002": {"encrypted": True, "kms_key_id": "arn:aws:kms:us-east-1:123:key/abc", "state": "in-use", "attachments": []}
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-2.2.1-VOL", "PASS")


# ── CIS-EC2-2.2.2 Snapshots no públicos ──────────────────────────────────────

class TestSnapshotsNotPublic:

    def test_fail_when_snapshot_is_public(self):
        raw = _base_raw()
        raw["ebs_snapshots"] = {
            "snap-001": {"encrypted": False, "is_public": True}
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-2.2.2", "FAIL")

    def test_pass_when_snapshot_is_private(self):
        raw = _base_raw()
        raw["ebs_snapshots"] = {
            "snap-002": {"encrypted": True, "is_public": False}
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-2.2.2", "PASS")


# ── CIS-EC2-5.6 IMDSv2 ───────────────────────────────────────────────────────

class TestIMDSv2:

    def test_fail_when_imdsv2_not_enforced(self):
        raw = _base_raw()
        raw["instances"] = {
            "i-001": _instance("i-001", imdsv2_required=False, imdsv2_enforced=False)
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-5.6", "FAIL")

    def test_pass_when_imdsv2_enforced(self):
        raw = _base_raw()
        raw["instances"] = {"i-002": _instance("i-002")}
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-5.6", "PASS")

    def test_skip_stopped_instances(self):
        raw = _base_raw()
        raw["instances"] = {
            "i-003": _instance("i-003", state="stopped", imdsv2_enforced=False)
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_no_finding(findings, "CIS-EC2-5.6", "FAIL")


# ── CIS-EC2-5.2 Security groups sin ingreso abierto ──────────────────────────

class TestSecurityGroupsNoOpenIngress:

    def test_fail_when_sg_open_to_world(self):
        raw = _base_raw()
        raw["security_groups"] = {
            "sg-001": _sg("sg-001", open_to_world=True, exposed_port_details=[
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "exposed_sensitive_ports": [22]}
            ])
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-5.2", "FAIL")

    def test_pass_when_sg_restricted(self):
        raw = _base_raw()
        raw["security_groups"] = {"sg-002": _sg("sg-002")}
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-5.2", "PASS")


# ── CIS-EC2-5.4 Default SG sin reglas ────────────────────────────────────────

class TestDefaultSGNoRules:

    def test_fail_when_default_sg_has_rules(self):
        raw = _base_raw()
        raw["security_groups"] = {
            "sg-default": _sg("sg-default",
                is_default=True,
                inbound_rules=[{"IpProtocol": "-1"}],
                outbound_rules=[{"IpProtocol": "-1"}],
            )
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-5.4", "FAIL")

    def test_pass_when_default_sg_has_no_rules(self):
        raw = _base_raw()
        raw["security_groups"] = {
            "sg-default": _sg("sg-default", is_default=True)
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-5.4", "PASS")


# ── CIS-EC2-3.9 VPC Flow Logs ────────────────────────────────────────────────

class TestVPCFlowLogs:

    def test_fail_when_no_flow_logs(self):
        raw = _base_raw()
        raw["vpcs"] = {
            "vpc-001": {"is_default": False, "has_flow_logs": False, "flow_logs_all_traffic": False}
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-3.9", "FAIL")

    def test_pass_when_flow_logs_enabled(self):
        raw = _base_raw()
        raw["vpcs"] = {
            "vpc-002": {"is_default": False, "has_flow_logs": True, "flow_logs_all_traffic": True}
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "CIS-EC2-3.9", "PASS")


# ── WAF-EC2-SSM-01 SSM managed ───────────────────────────────────────────────

class TestSSMManaged:

    def test_fail_when_not_ssm_managed(self):
        raw = _base_raw()
        raw["instances"] = {
            "i-004": _instance("i-004", ssm_managed=False)
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "WAF-EC2-SSM-01", "FAIL")

    def test_pass_when_ssm_managed(self):
        raw = _base_raw()
        raw["instances"] = {"i-005": _instance("i-005")}
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "WAF-EC2-SSM-01", "PASS")


# ── WAF-EC2-EIP-01 Elastic IPs sin asignar ───────────────────────────────────

class TestUnusedEIPs:

    def test_fail_when_eip_unassigned(self):
        raw = _base_raw()
        raw["elastic_ips"] = [{"public_ip": "52.1.2.3", "is_unassigned": True}]
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "WAF-EC2-EIP-01", "FAIL")

    def test_pass_when_eip_assigned(self):
        raw = _base_raw()
        raw["elastic_ips"] = [{"public_ip": "52.1.2.4", "is_unassigned": False}]
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "WAF-EC2-EIP-01", "PASS")


# ── WAF-EC2-PIP-01 Sin IP pública directa ────────────────────────────────────

class TestNoDirectPublicIP:

    def test_fail_when_directly_exposed(self):
        raw = _base_raw()
        raw["instances"] = {
            "i-006": _instance("i-006",
                public_ip="1.2.3.4",
                exposure_type="direct_public",
                directly_exposed=True,
            )
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "WAF-EC2-PIP-01", "FAIL")

    def test_pass_when_behind_elb(self):
        raw = _base_raw()
        raw["instances"] = {
            "i-007": _instance("i-007",
                public_ip="1.2.3.5",
                exposure_type="behind_elb",
                behind_elb=True,
                directly_exposed=False,
            )
        }
        output   = make_collector_output("ec2", raw)
        findings = ec2_analyzer.analyze(output)
        assert_finding(findings, "WAF-EC2-PIP-01", "PASS")


# ── Test integración — configuración segura ───────────────────────────────────

class TestSecureConfiguration:

    def test_no_critical_fails_with_secure_config(self, ec2_raw_secure):
        output   = make_collector_output("ec2", ec2_raw_secure)
        findings = ec2_analyzer.analyze(output)
        critical_fails = [
            f for f in findings
            if f.status.value == "FAIL" and f.severity.value == "CRITICAL"
        ]
        assert len(critical_fails) == 0, (
            f"Expected no CRITICAL fails, got: "
            f"{[(f.control_id, f.message) for f in critical_fails]}"
        )