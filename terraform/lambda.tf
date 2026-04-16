# =============================================================================
# Lambda: threat-log-enricher (CloudWatch Logs → Step Functions)
# =============================================================================

data "archive_file" "threat_log_enricher" {
  type        = "zip"
  source_file = "${path.module}/lambda/threat-log-enricher/lambda_function.py"
  output_path = "${path.module}/.build/threat-log-enricher.zip"
}

resource "aws_lambda_function" "threat_log_enricher" {
  function_name = "threat-log-enricher"
  description   = "Decodes CloudWatch Logs subscription payloads and enriches high-risk CloudTrail events."
  role          = aws_iam_role.threat_detection_lambda.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.threat_log_enricher.output_path
  source_code_hash = data.archive_file.threat_log_enricher.output_base64sha256

  timeout     = 60
  memory_size = 256

  environment {
    variables = {
      STATE_MACHINE_ARN = aws_sfn_state_machine.threat_detection_pipeline.arn
    }
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Logs subscription — high-risk CloudTrail events only (matches Lambda filter)
# -----------------------------------------------------------------------------

locals {
  # Matches threat-log-enricher HIGH_RISK_EVENTS; reduces Lambda invocations vs. forwarding all CloudTrail logs.
  high_risk_event_filter_pattern = join(" || ", [
    for name in [
      "ConsoleLogin",
      "CreateUser",
      "DeleteUser",
      "AttachUserPolicy",
      "PutUserPolicy",
      "CreateAccessKey",
      "DeleteTrail",
      "StopLogging",
      "DeleteBucket",
      "PutBucketPolicy",
      "AuthorizeSecurityGroupIngress",
      "CreateVpc",
      "RunInstances",
      "AssumeRoleWithWebIdentity",
      "GetSecretValue",
      "DeleteSecret",
    ] : "($.eventName = \"${name}\")"
  ])
  high_risk_event_filter_pattern_wrapped = "{ (${local.high_risk_event_filter_pattern}) }"
}

resource "aws_lambda_permission" "threat_log_enricher_cloudwatch_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_log_enricher.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cloudtrail_threat_detection.arn}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "threat_log_enricher_high_risk" {
  name            = "high-risk-event-filter"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail_threat_detection.name
  filter_pattern  = local.high_risk_event_filter_pattern_wrapped
  destination_arn = aws_lambda_function.threat_log_enricher.arn

  depends_on = [aws_lambda_permission.threat_log_enricher_cloudwatch_logs]
}

# =============================================================================
# Lambda: threat-bedrock-analyzer (Bedrock threat scoring)
# =============================================================================

data "archive_file" "threat_bedrock_analyzer" {
  type        = "zip"
  source_file = "${path.module}/lambda/threat-bedrock-analyzer/lambda_function.py"
  output_path = "${path.module}/.build/threat-bedrock-analyzer.zip"
}

resource "aws_lambda_function" "threat_bedrock_analyzer" {
  function_name = "threat-bedrock-analyzer"
  description   = "Calls Bedrock Claude Haiku to analyze enriched CloudTrail events for threat scoring."
  role          = aws_iam_role.threat_detection_lambda.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.threat_bedrock_analyzer.output_path
  source_code_hash = data.archive_file.threat_bedrock_analyzer.output_base64sha256

  timeout     = 30
  memory_size = 256
}

# =============================================================================
# Lambda: threat-record-writer (DynamoDB persistence)
# =============================================================================

data "archive_file" "threat_record_writer" {
  type        = "zip"
  source_file = "${path.module}/lambda/threat-record-writer/lambda_function.py"
  output_path = "${path.module}/.build/threat-record-writer.zip"
}

resource "aws_lambda_function" "threat_record_writer" {
  function_name = "threat-record-writer"
  description   = "Writes analyzed threat events to DynamoDB."
  role          = aws_iam_role.threat_detection_lambda.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.threat_record_writer.output_path
  source_code_hash = data.archive_file.threat_record_writer.output_base64sha256

  timeout     = 30
  memory_size = 256
}

# =============================================================================
# Lambda: threat-email-alerter (SES HTML alerts)
# =============================================================================

data "archive_file" "threat_email_alerter" {
  type        = "zip"
  source_file = "${path.module}/lambda/threat-email-alerter/lambda_function.py"
  output_path = "${path.module}/.build/threat-email-alerter.zip"
}

resource "aws_lambda_function" "threat_email_alerter" {
  function_name = "threat-email-alerter"
  description   = "Sends HTML threat alert emails via SES when threat score is at or above threshold."
  role          = aws_iam_role.threat_detection_lambda.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.threat_email_alerter.output_path
  source_code_hash = data.archive_file.threat_email_alerter.output_base64sha256

  timeout     = 30
  memory_size = 256

  environment {
    variables = {
      SES_FROM_EMAIL = var.ses_identity_email
      SES_TO_EMAIL   = var.ses_alert_to_email != "" ? var.ses_alert_to_email : var.ses_identity_email
    }
  }
}

# =============================================================================
# IAM: shared role for all threat-detection Lambdas
# =============================================================================

resource "aws_iam_role" "threat_detection_lambda" {
  name = "ThreatDetectionLambdaRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Inline policy: Bedrock, DynamoDB, CloudWatch Logs, SES

resource "aws_iam_role_policy" "threat_detection_lambda" {
  name = "ThreatDetectionLambdaPolicy"
  role = aws_iam_role.threat_detection_lambda.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "BedrockInvoke"
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-20240307-v1:0"
      },
      {
        Sid    = "DynamoDBWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
        ]
        Resource = aws_dynamodb_table.threat_detection_events.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid      = "SESSendEmail"
        Effect   = "Allow"
        Action   = ["ses:SendEmail", "ses:SendRawEmail"]
        Resource = aws_ses_email_identity.this.arn
      },
    ]
  })
}

# Inline policy: log enricher calls states:StartExecution on this pipeline

resource "aws_iam_role_policy" "threat_detection_sfn_start" {
  name = "ThreatDetectionSFNStartPolicy"
  role = aws_iam_role.threat_detection_lambda.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StartStepFunctions"
        Effect   = "Allow"
        Action   = "states:StartExecution"
        Resource = aws_sfn_state_machine.threat_detection_pipeline.arn
      },
    ]
  })
}
