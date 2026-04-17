# No ingress/egress rules: remediator attaches this SG to EC2 instances for network isolation.
resource "aws_security_group" "quarantine_sg" {
  name                   = "quarantine-sg"
  description            = "SOAR: Zero-traffic isolation for compromised instances."
  vpc_id                 = aws_vpc.default_vpc.id
  revoke_rules_on_delete = true

  tags = {
    Purpose   = "QuarantineSG"
    ManagedBy = "ThreatDetectionSOAR"
  }
}
