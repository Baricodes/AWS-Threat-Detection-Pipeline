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
    Comment = "AI-Powered Threat Detection + SOAR Remediation Pipeline"
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
                "result.$" = "$.Payload"
              }
              ResultPath = "$.analysisResult"
              Next       = "MergeAnalysis"
              Retry = [
                {
                  ErrorEquals     = ["Lambda.ServiceException"]
                  IntervalSeconds = 5
                  MaxAttempts     = 2
                  BackoffRate     = 2
                }
              ]
            }
            MergeAnalysis = {
              Type = "Pass"
              Parameters = {
                "accountId.$"         = "$.analysisResult.result.accountId"
                "awsRegion.$"         = "$.analysisResult.result.awsRegion"
                "eventName.$"         = "$.analysisResult.result.eventName"
                "eventTime.$"         = "$.analysisResult.result.eventTime"
                "threatId.$"          = "$.analysisResult.result.threatId"
                "sourceIPAddress.$"   = "$.analysisResult.result.sourceIPAddress"
                "userIdentity.$"      = "$.analysisResult.result.userIdentity"
                "responseElements.$"  = "$.analysisResult.result.responseElements"
                "requestParameters.$" = "$.analysisResult.result.requestParameters"
                "threatScore.$"       = "$.analysisResult.result.threatScore"
                "severity.$"          = "$.analysisResult.result.severity"
                "summary.$"           = "$.analysisResult.result.analysis.summary"
                "reasoning.$"         = "$.analysisResult.result.analysis.reasoning"
                "indicators.$"        = "$.analysisResult.result.analysis.indicators"
                "recommendedAction.$" = "$.analysisResult.result.analysis.recommendedAction"
                "eventId.$"           = "$.analysisResult.result.eventId"
                "originalEventId.$"   = "$.analysisResult.result.originalEventId"
                "userArn.$"           = "$.analysisResult.result.userArn"
                "userType.$"          = "$.analysisResult.result.userType"
                "userAgent.$"         = "$.analysisResult.result.userAgent"
                "errorCode.$"         = "$.analysisResult.result.errorCode"
                "errorMessage.$"      = "$.analysisResult.result.errorMessage"
                "ingestedAt.$"        = "$.analysisResult.result.ingestedAt"
                "rawEvent.$"          = "$.analysisResult.result.rawEvent"
                analysis = {
                  "summary.$"           = "$.analysisResult.result.analysis.summary"
                  "reasoning.$"         = "$.analysisResult.result.analysis.reasoning"
                  "indicators.$"        = "$.analysisResult.result.analysis.indicators"
                  "recommendedAction.$" = "$.analysisResult.result.analysis.recommendedAction"
                }
              }
              Next = "ChoosePath"
            }
            ChoosePath = {
              Type = "Choice"
              Choices = [
                {
                  Variable                 = "$.threatScore"
                  NumericGreaterThanEquals = 9
                  Next                     = "RemediateThreat"
                },
                {
                  Variable                 = "$.threatScore"
                  NumericGreaterThanEquals = 7
                  Next                     = "WriteThreatRecord"
                },
              ]
              Default = "WriteThreatRecord"
            }
            RemediateThreat = {
              Type     = "Task"
              Resource = "arn:aws:states:::lambda:invoke"
              Parameters = {
                FunctionName = "threat-remediator"
                "Payload.$"  = "$"
              }
              ResultSelector = {
                "result.$" = "$.Payload"
              }
              ResultPath = "$.remediationOutput"
              Next       = "WriteThreatRecordWithRemediation"
              Retry = [
                {
                  ErrorEquals     = ["Lambda.ServiceException"]
                  IntervalSeconds = 5
                  MaxAttempts     = 1
                  BackoffRate     = 2
                }
              ]
              Catch = [
                {
                  ErrorEquals = ["States.ALL"]
                  Next        = "WriteThreatRecord"
                  ResultPath  = "$.remediationError"
                }
              ]
            }
            WriteThreatRecordWithRemediation = {
              Type     = "Task"
              Resource = "arn:aws:states:::lambda:invoke"
              Parameters = {
                FunctionName = "threat-record-writer"
                "Payload.$"  = "$"
              }
              ResultPath = null
              Next       = "SendCriticalAlert"
              Retry = [
                {
                  ErrorEquals     = ["Lambda.ServiceException"]
                  IntervalSeconds = 5
                  MaxAttempts     = 2
                  BackoffRate     = 2
                }
              ]
            }
            SendCriticalAlert = {
              Type     = "Task"
              Resource = "arn:aws:states:::lambda:invoke"
              Parameters = {
                FunctionName = "threat-email-alerter"
                "Payload.$"  = "$"
              }
              ResultPath = null
              End        = true
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
                "Payload.$"  = "$"
              }
              ResultPath = null
              Next       = "CheckScoreForAlert"
              Retry = [
                {
                  ErrorEquals     = ["Lambda.ServiceException"]
                  IntervalSeconds = 5
                  MaxAttempts     = 2
                  BackoffRate     = 2
                }
              ]
            }
            CheckScoreForAlert = {
              Type = "Choice"
              Choices = [
                {
                  Variable                 = "$.threatScore"
                  NumericGreaterThanEquals = 7
                  Next                     = "SendEmailAlert"
                },
              ]
              Default = "End"
            }
            SendEmailAlert = {
              Type     = "Task"
              Resource = "arn:aws:states:::lambda:invoke"
              Parameters = {
                FunctionName = "threat-email-alerter"
                "Payload.$"  = "$"
              }
              ResultPath = null
              End        = true
              Retry = [
                {
                  ErrorEquals     = ["Lambda.ServiceException"]
                  IntervalSeconds = 5
                  MaxAttempts     = 2
                  BackoffRate     = 2
                }
              ]
            }
            End = {
              Type = "Succeed"
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
