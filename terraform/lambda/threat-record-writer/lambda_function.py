import boto3
import os
from datetime import datetime, timezone, timedelta
from decimal import Decimal

dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

TABLE_NAME = "ThreatDetectionEvents"
ALERT_THRESHOLD = 7  # Alert on threat scores >= 7


def lambda_handler(event, context):
    """
    Persists analyzed threat event to DynamoDB.
    Sends SNS alert if threat score meets threshold.
    """
    table = dynamodb.Table(TABLE_NAME)

    analysis = event.get("analysis", {})
    threat_score = event.get("threatScore", 0)

    # TTL: keep records for 90 days
    ttl_timestamp = int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp())

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
    }

    table.put_item(Item=item)


    return {
        "statusCode": 200,
        "eventId": event.get("eventId"),
        "threatScore": threat_score,
        "severity": event.get("severity"),
        "alertSent": threat_score >= ALERT_THRESHOLD,
    }
