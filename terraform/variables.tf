variable "aws_region" {
  description = "AWS region for resources."
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS account ID for this deployment."
  type        = string
}
