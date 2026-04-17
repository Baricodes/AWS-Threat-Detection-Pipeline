# Delivery target for aws_cloudtrail.threat_detection; must exist before the trail enables log delivery.
resource "aws_cloudwatch_log_group" "cloudtrail_threat_detection" {
  name              = "/aws/cloudtrail/threat-detection"
  retention_in_days = 30
}
