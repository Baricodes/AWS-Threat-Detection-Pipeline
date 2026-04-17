resource "aws_ses_email_identity" "this" {
  email = var.ses_identity_email
}
