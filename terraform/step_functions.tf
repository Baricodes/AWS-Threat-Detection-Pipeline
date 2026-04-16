resource "aws_iam_role" "threat_detection_step_functions" {
  name = "ThreatDetectionStepFunctionsRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "threat_detection_step_functions" {
  name = "ThreatDetectionStepFunctionsPolicy"
  role = aws_iam_role.threat_detection_step_functions.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeLambda"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:threat-*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:GetLogDelivery",
          "logs:ListLogDeliveries",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:DescribeLogGroups",
          "logs:DescribeResourcePolicies",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_sfn_state_machine" "threat_detection_pipeline" {
  name     = "ThreatDetectionPipeline"
  role_arn = aws_iam_role.threat_detection_step_functions.arn
  type     = "STANDARD"

  definition = jsonencode({
    Comment = "AI-Powered Cloud Threat Detection Pipeline"
    StartAt = "ProcessEachEvent"
    States = {
      ProcessEachEvent = {
        Type           = "Map"
        ItemsPath      = "$.eventsToAnalyze"
        MaxConcurrency = 5
        Iterator = {
          StartAt = "AnalyzeThreat"
          States = {
            AnalyzeThreat = {
              Type     = "Task"
              Resource = "arn:aws:states:::lambda:invoke"
              Parameters = {
                FunctionName = "threat-bedrock-analyzer"
                Payload = {
                  "enrichedEvent.$" = "$"
                }
              }
              ResultSelector = {
                "analysisPayload.$" = "$.Payload"
              }
              ResultPath = "$.analysisResult"
              Next       = "WriteThreatRecord"
              Retry = [
                {
                  ErrorEquals     = ["Lambda.ServiceException"]
                  IntervalSeconds = 5
                  MaxAttempts     = 2
                  BackoffRate     = 2
                }
              ]
              Catch = [
                {
                  ErrorEquals = ["States.ALL"]
                  Next        = "SkipEvent"
                  ResultPath  = "$.error"
                }
              ]
            }
            WriteThreatRecord = {
              Type     = "Task"
              Resource = "arn:aws:states:::lambda:invoke"
              Parameters = {
                FunctionName = "threat-record-writer"
                "Payload.$"  = "$.analysisResult.analysisPayload"
              }
              ResultSelector = {
                "recordPayload.$" = "$.Payload"
              }
              ResultPath = "$.recordResult"
              Next       = "SendEmailAlert"
            }
            SendEmailAlert = {
              Type     = "Task"
              Resource = "arn:aws:states:::lambda:invoke"
              Parameters = {
                FunctionName = "threat-email-alerter"
                "Payload.$"  = "$.analysisResult.analysisPayload"
              }
              End = true
              Catch = [
                {
                  ErrorEquals = ["States.ALL"]
                  Next        = "SkipEvent"
                  ResultPath  = "$.error"
                }
              ]
            }
            SkipEvent = {
              Type = "Pass"
              End  = true
            }
          }
        }
        Next = "PipelineComplete"
      }
      PipelineComplete = {
        Type = "Pass"
        Result = {
          message = "Threat detection pipeline completed"
        }
        End = true
      }
    }
  })
}
