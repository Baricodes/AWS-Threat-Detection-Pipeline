import json
import base64
import gzip
import uuid
from datetime import datetime, timezone

# High-risk event patterns worth analyzing
HIGH_RISK_EVENTS = {
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
}


def lambda_handler(event, context):
    """
    Receives CloudWatch Logs subscription filter data.
    Decodes, decompresses, and extracts CloudTrail events.
    Filters to high-risk events only.
    Returns enriched event list for Step Functions.
    """
    # CloudWatch Logs delivers data as base64-encoded gzipped JSON
    raw_data = event.get("awslogs", {}).get("data", "")

    if not raw_data:
        # If triggered directly (for testing), pass through
        return event

    # Decode and decompress
    compressed = base64.b64decode(raw_data)
    decompressed = gzip.decompress(compressed)
    log_data = json.loads(decompressed)

    enriched_events = []

    for log_event in log_data.get("logEvents", []):
        try:
            ct_event = json.loads(log_event["message"])
        except (json.JSONDecodeError, KeyError):
            continue

        event_name = ct_event.get("eventName", "")

        # Filter: only process high-risk events
        if event_name not in HIGH_RISK_EVENTS:
            continue

        # Enrich with derived fields
        source_ip = ct_event.get("sourceIPAddress", "unknown")
        user_identity = ct_event.get("userIdentity", {})

        enriched = {
            "eventId": str(uuid.uuid4()),
            "originalEventId": ct_event.get("eventID", ""),
            "eventName": event_name,
            "eventTime": ct_event.get("eventTime", ""),
            "awsRegion": ct_event.get("awsRegion", ""),
            "sourceIPAddress": source_ip,
            "userAgent": ct_event.get("userAgent", ""),
            "userType": user_identity.get("type", ""),
            "userArn": user_identity.get("arn", ""),
            "accountId": user_identity.get("accountId", ""),
            "errorCode": ct_event.get("errorCode", ""),
            "errorMessage": ct_event.get("errorMessage", ""),
            "requestParameters": json.dumps(ct_event.get("requestParameters", {})),
            "ingestedAt": datetime.now(timezone.utc).isoformat(),
            "rawEvent": json.dumps(ct_event),
        }

        enriched_events.append(enriched)

    return {
        "statusCode": 200,
        "eventsToAnalyze": enriched_events,
        "eventCount": len(enriched_events),
    }
