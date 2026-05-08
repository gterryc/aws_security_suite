# ─────────────────────────────────────────────────────────────
# [TF-GD] Módulo GuardDuty — configuración de prueba
#
# Seguro (PASS):
#   - Detector habilitado con frecuencia FIFTEEN_MINUTES
#
# Inseguro (FAIL):
#   - Sin exportación de findings configurada
#   - Protection plans deshabilitados
# ─────────────────────────────────────────────────────────────

variable "prefix" { type = string }
variable "tags" { type = map(string) }

# Detector GuardDuty habilitado
# Protection plans deshabilitados por defecto — genera WAF-GD-PPL-01 FAIL
# Sin export config — genera WAF-GD-EXP-01 FAIL
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES" # PASS en WAF-GD-FRQ-01
  tags                         = merge(var.tags, { Purpose = "audit-test-guardduty" })
}
