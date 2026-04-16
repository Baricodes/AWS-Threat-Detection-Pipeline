output "aws_region" {
  description = "AWS region in use."
  value       = var.aws_region
}

output "ses_identity_email" {
  description = "SES email identity address (verify via link sent by AWS after apply)."
  value       = aws_ses_email_identity.this.email
}
