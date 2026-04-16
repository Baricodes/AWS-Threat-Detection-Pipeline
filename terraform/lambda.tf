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
}

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

data "archive_file" "threat_record_writer" {
  type        = "zip"
  source_file = "${path.module}/lambda/threat-record-writer/lambda_function.py"
  output_path = "${path.module}/.build/threat-record-writer.zip"
}

resource "aws_lambda_function" "threat_record_writer" {
  function_name = "threat-record-writer"
  description   = "Writes analyzed threat events to DynamoDB and publishes high-score alerts to SNS."
  role          = aws_iam_role.threat_detection_lambda.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.threat_record_writer.output_path
  source_code_hash = data.archive_file.threat_record_writer.output_base64sha256

  timeout     = 30
  memory_size = 256
  
}

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
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "arn:aws:sns:${var.aws_region}:${var.aws_account_id}:threat-detection-alerts"
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
    ]
  })
}
