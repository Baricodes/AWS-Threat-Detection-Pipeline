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
    StartAt = "EnrichLogEvent"
    States = {
      EnrichLogEvent = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = "threat-log-enricher"
          "Payload.$"  = "$"
        }
        ResultPath = "$.enrichResult"
        Next       = "CheckEventsFound"
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleError"
            ResultPath  = "$.error"
          }
        ]
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2
          }
        ]
      }
      CheckEventsFound = {
        Type = "Choice"
        Choices = [
          {
            Variable           = "$.enrichResult.Payload.eventCount"
            NumericGreaterThan = 0
            Next               = "ProcessEachEvent"
          }
        ]
        Default = "NoThreatsFound"
      }
      ProcessEachEvent = {
        Type           = "Map"
        ItemsPath      = "$.enrichResult.Payload.eventsToAnalyze"
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
            }
            WriteThreatRecord = {
              Type     = "Task"
              Resource = "arn:aws:states:::lambda:invoke"
              Parameters = {
                FunctionName = "threat-record-writer"
                "Payload.$"  = "$.analysisResult.Payload"
              }
              End = true
            }
          }
        }
        Next = "PipelineComplete"
      }
      NoThreatsFound = {
        Type = "Pass"
        Result = {
          message = "No high-risk events in this batch"
        }
        End = true
      }
      PipelineComplete = {
        Type = "Pass"
        Result = {
          message = "Threat detection pipeline completed"
        }
        End = true
      }
      HandleError = {
        Type = "Pass"
        Result = {
          message = "Pipeline encountered an error"
        }
        End = true
      }
    }
  })
}
