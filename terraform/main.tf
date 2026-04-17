# =============================================================================
# Root module — threat detection pipeline (flat layout)
# =============================================================================
#
#   versions.tf, providers.tf  — toolchain and AWS provider
#   variables.tf, outputs.tf   — inputs and exported values
#   vpc.tf                     — VPC for optional workloads
#   s3.tf, cloudwatch.tf       — CloudTrail log destinations
#   cloudtrail.tf              — trail and delivery roles
#   dynamodb.tf                — threat event table
#   ses.tf                     — SES identity for alerts
#   lambda.tf                  — Lambdas, log subscription, Lambda IAM
#   step_functions.tf          — state machine and Step Functions IAM
#
# =============================================================================
