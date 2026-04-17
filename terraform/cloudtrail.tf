# =============================================================================
# CloudTrail: trail + IAM for delivery to CloudWatch Logs and S3
# =============================================================================

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name = "CloudTrailToCloudWatchRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# AWS does not publish a managed policy for this role; see:
# https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-required-policy-for-cloudwatch-logs.html
resource "aws_iam_role_policy" "cloudtrail_cloudwatch_logs" {
  name = "cloudtrail-cloudwatch-logs-delivery"
  role = aws_iam_role.cloudtrail_to_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailCreateLogStream20141101"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail_threat_detection.arn}:log-stream:${data.aws_caller_identity.current.account_id}_CloudTrail_*"
      },
      {
        Sid    = "AWSCloudTrailPutLogEvents20141101"
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail_threat_detection.arn}:log-stream:${data.aws_caller_identity.current.account_id}_CloudTrail_*"
      }
    ]
  })
}

# Multi-region management events; logs land in S3 (archive) and CloudWatch (real-time pipeline)

resource "aws_cloudtrail" "threat_detection" {
  name           = "threat-detection-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.id

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail_threat_detection.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cloudwatch.arn

  include_global_service_events = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_iam_role_policy.cloudtrail_cloudwatch_logs,
  ]
}
