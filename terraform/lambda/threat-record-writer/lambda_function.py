"""Persist one analyzed event to DynamoDB.

Reads optional remediationOutput from threat-remediator (critical path).
"""
import boto3
from datetime import datetime, timedelta, timezone
from decimal import Decimal

dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

TABLE_NAME = "ThreatDetectionEvents"
# Align with Step Functions CheckScoreForAlert and email alerter.
ALERT_THRESHOLD = 7
TTL_DAYS = 90


def lambda_handler(event, context):
    table = dynamodb.Table(TABLE_NAME)

    analysis = event.get("analysis", {})
    threat_score = event.get("threatScore", 0)

    ttl_timestamp = int(
        (datetime.now(timezone.utc) + timedelta(days=TTL_DAYS)).timestamp()
    )

    # RemediateThreat: Lambda output → remediationOutput.result.remediationResult.
    remediation_result = (
        event.get("remediationOutput", {})
        .get("result", {})
        .get("remediationResult", {})
    )

    item = {
        "eventId": event.get("eventId", "unknown"),
        "timestamp": event.get("eventTime", datetime.now(timezone.utc).isoformat()),
        "eventName": event.get("eventName", ""),
        "severity": event.get("severity", "UNKNOWN"),
        "threatScore": Decimal(str(threat_score)),
        "sourceIPAddress": event.get("sourceIPAddress", ""),
        "userArn": event.get("userArn", ""),
        "awsRegion": event.get("awsRegion", ""),
        "summary": analysis.get("summary", ""),
        "reasoning": analysis.get("reasoning", ""),
        "indicators": analysis.get("indicators", []),
        "recommendedAction": analysis.get("recommendedAction", ""),
        "rawEvent": event.get("rawEvent", ""),
        "ingestedAt": event.get("ingestedAt", ""),
        "ttl": ttl_timestamp,
        "remediationStatus": remediation_result.get("status", "NOT_TRIGGERED"),
        "remediationActions": remediation_result.get("actionsTaken", []),
        "remediationTime": remediation_result.get("remediationTime"),
        "remediationError": remediation_result.get("error"),
    }

    table.put_item(Item=item)

    return {
        "statusCode": 200,
        "eventId": event.get("eventId"),
        "threatScore": threat_score,
        "severity": event.get("severity"),
        "meetsAlertThreshold": threat_score >= ALERT_THRESHOLD,
    }
