# Verified sender for threat-email-alerter and remediator notifications; complete verification in SES console after apply.
resource "aws_ses_email_identity" "this" {
  email = var.ses_identity_email
}
