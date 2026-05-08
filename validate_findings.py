"""
Script de validación de findings esperados.
Uso: python3 validate_findings.py
"""
import json
import glob
import sys

# Encontrar reporte más reciente
reports = sorted(glob.glob("outputs/*/json/report_*.json"))
if not reports:
    reports = sorted(glob.glob("outputs/json/report_*.json"))

if not reports:
    print("❌ No se encontró ningún reporte JSON.")
    sys.exit(1)

report_path = reports[-1]
print(f"Usando reporte: {report_path}\n")
report = json.load(open(report_path))

# Construir mapa priorizando FAIL sobre PASS
# Si cualquier finding del control es FAIL, el control se marca como FAIL
findings_map: dict[str, str] = {}
for f in report["findings"]:
    cid    = f["control_id"]
    status = f["status"]
    if findings_map.get(cid) != "FAIL":
        findings_map[cid] = status

EXPECTED_FAILS = [
    "CIS-VPC-3.9",
    "WAF-EC2-SUB-01",
    "CIS-IAM-1.8",
    "CIS-IAM-1.10",
    "CIS-IAM-1.15",
    "CIS-IAM-1.16",
    "WAF-S3-ENC-CMK-01",   # AES256 default de AWS — no usa CMK
    "CIS-S3-2.1.1",
    "CIS-S3-2.6",
    "WAF-S3-VER-01",
    "CIS-EC2-5.2",
    "CIS-EC2-5.6",
    "CIS-EC2-2.2.2",
    "CIS-RDS-2.3.2",
    "CIS-RDS-2.3.1",
    "CIS-RDS-2.3.3",
    "WAF-GD-EXP-01",
]

print("Validación de findings esperados:")
print(f"{'Control ID':<30} {'Esperado':<12} {'Obtenido':<12} {'✓/✗'}")
print("-" * 60)

all_ok = True
for control in EXPECTED_FAILS:
    expected = "FAIL"
    obtained = findings_map.get(control, "NOT FOUND")
    ok       = obtained == expected
    if not ok:
        all_ok = False
    icon = "✅" if ok else "❌"
    print(f"{control:<30} {expected:<12} {obtained:<12} {icon}")

print()

# Resumen del reporte
total      = report.get("total_controls", 0)
passed     = report.get("passed_controls", 0)
failed     = report.get("failed_controls", 0)
score      = report.get("global_score", 0)
severities = report.get("by_severity", {})

print(f"Score global   : {score}%")
print(f"Total controls : {total}")
print(f"Passed         : {passed}")
print(f"Failed         : {failed}")
print(f"Por severidad  : {severities}")
print()

if all_ok:
    print("✅ Todos los findings esperados fueron detectados correctamente.")
else:
    print("❌ Algunos findings esperados no fueron detectados.")
    sys.exit(1)