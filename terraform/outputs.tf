# =============================================================================
# Outputs
# =============================================================================

output "aws_region" {
  description = "AWS region in use."
  value       = var.aws_region
}

# --- SES ---

output "ses_identity_email" {
  description = "SES email identity address (verify via link sent by AWS after apply)."
  value       = aws_ses_email_identity.this.email
}

# --- IAM (troubleshooting / cross-stack references) ---

output "threat_detection_lambda_role_arn" {
  description = "IAM role ARN for the threat detection Lambda function."
  value       = aws_iam_role.threat_detection_lambda.arn
}

output "threat_detection_step_functions_role_arn" {
  description = "IAM role ARN for threat detection Step Functions state machines."
  value       = aws_iam_role.threat_detection_step_functions.arn
}
