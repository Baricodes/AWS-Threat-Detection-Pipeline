"""CloudWatch Logs subscription target: decode gzipped CloudTrail batches.

Filter by event name, start Step Functions. Event names in HIGH_RISK_EVENTS
must match terraform/lambda.tf local high_risk_event_filter_pattern.
"""
import base64
import gzip
import json
import os
import uuid
from datetime import datetime, timezone

import boto3

sfn = boto3.client("stepfunctions")
STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN", "")

# Same set as the subscription filter (lambda.tf); change both together.
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
    raw_data = event.get("awslogs", {}).get("data", "")

    if not raw_data:
        return event

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
        if event_name not in HIGH_RISK_EVENTS:
            continue

        user_identity = ct_event.get("userIdentity", {})
        enriched = {
            "eventId": str(uuid.uuid4()),
            "originalEventId": ct_event.get("eventID", ""),
            "eventName": event_name,
            "eventTime": ct_event.get("eventTime", ""),
            "awsRegion": ct_event.get("awsRegion", ""),
            "sourceIPAddress": ct_event.get("sourceIPAddress", "unknown"),
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

    if enriched_events and STATE_MACHINE_ARN:
        payload = {
            "eventsToAnalyze": enriched_events,
            "eventCount": len(enriched_events),
        }
        sfn.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=f"execution-{uuid.uuid4()}",
            input=json.dumps(payload),
        )

    return {
        "statusCode": 200,
        "eventsProcessed": len(enriched_events),
    }
