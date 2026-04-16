resource "aws_cloudwatch_log_group" "cloudtrail_threat_detection" {
  name              = "/aws/cloudtrail/threat-detection"
  retention_in_days = 30
}
