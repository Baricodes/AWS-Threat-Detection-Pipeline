"""Step Functions task for threatScore ≥ 9.

IAM containment (keys + deny policy) or EC2 quarantine SG; optional SES alert.
"""
import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
ec2 = boto3.client("ec2")

# terraform: aws_security_group.quarantine_sg
QUARANTINE_SG_ID = os.environ.get("QUARANTINE_SG_ID")
DENY_POLICY_ARN = os.environ.get(
    "DENY_POLICY_ARN", "arn:aws:iam::aws:policy/AWSDenyAll"
)

SES_SENDER = os.environ.get("SES_SENDER_EMAIL")
SES_RECIPIENT = os.environ.get("SES_RECIPIENT_EMAIL")

CREDENTIAL_EVENTS = {
    "CreateAccessKey",
    "GetSecretValue",
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateUser",
    "AssumeRoleWithWebIdentity",
}
INFRASTRUCTURE_EVENTS = {"RunInstances", "AuthorizeSecurityGroupIngress"}


def lambda_handler(event, context):
    logger.info("Remediation triggered: %s", json.dumps(event))

    event_name = event.get("eventName", "")
    user_identity = event.get("userIdentity", {})
    principal = user_identity.get("userName") or user_identity.get("arn", "UNKNOWN")
    threat_id = event.get("threatId", "")

    remediation = {
        "threatId": threat_id,
        "remediationTime": datetime.now(timezone.utc).isoformat(),
        "eventName": event_name,
        "principal": principal,
        "actionsTaken": [],
        "status": "COMPLETED",
        "error": None,
    }

    try:
        if event_name in CREDENTIAL_EVENTS:
            _remediate_iam(principal, remediation)

        elif event_name in INFRASTRUCTURE_EVENTS:
            _remediate_ec2(event, remediation)

        else:
            remediation["actionsTaken"].append(
                "NO_ACTION: event type not in remediation map"
            )
            remediation["status"] = "SKIPPED"

    except Exception as e:
        logger.error("Remediation error: %s", e)
        remediation["status"] = "FAILED"
        remediation["error"] = str(e)

    logger.info("Remediation result: %s", json.dumps(remediation))

    try:
        _send_remediation_alert(remediation)
    except Exception as e:
        logger.warning("Remediation alert email failed (non-fatal): %s", e)

    return {**event, "remediationResult": remediation}


def _send_remediation_alert(remediation):
    ses = boto3.client("ses", region_name="us-east-1")

    actions_html = "".join(
        f"<li style='margin:4px 0;'>{a}</li>"
        for a in remediation.get("actionsTaken", [])
    )

    body_html = f"""
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#A32D2D;padding:12px 20px;border-radius:6px 6px 0 0;">
        <h2 style="color:#fff;margin:0;font-size:16px;">
          CRITICAL — Automated Remediation Fired
        </h2>
      </div>
      <div style="border:1px solid #eee;padding:20px;border-radius:0 0 6px 6px;">
        <table style="width:100%;font-size:13px;border-collapse:collapse;">
          <tr><td style="color:#888;padding:6px 0;width:140px;">Threat ID</td>
              <td style="font-weight:500;">{remediation.get("threatId", "—")}</td></tr>
          <tr><td style="color:#888;padding:6px 0;">Event</td>
              <td style="font-weight:500;">{remediation.get("eventName", "—")}</td></tr>
          <tr><td style="color:#888;padding:6px 0;">Principal</td>
              <td style="font-weight:500;">{remediation.get("principal", "—")}</td></tr>
          <tr><td style="color:#888;padding:6px 0;">Remediation status</td>
              <td style="font-weight:500;">{remediation.get("status", "—")}</td></tr>
          <tr><td style="color:#888;padding:6px 0;">Time</td>
              <td style="font-weight:500;">{
                remediation.get("remediationTime", "—")
              }</td></tr>
        </table>
        <div style="margin-top:16px;">
          <p style="font-size:12px;color:#888;margin:0 0 6px;">Actions taken</p>
          <ul style="margin:0;padding-left:18px;font-size:13px;">
            {actions_html}
          </ul>
        </div>
      </div>
    </div>
    """

    subj = (
        f"[CRITICAL REMEDIATION] {remediation.get('eventName')} — "
        f"{remediation.get('principal')}"
    )
    ses.send_email(
        Source=SES_SENDER,
        Destination={"ToAddresses": [SES_RECIPIENT]},
        Message={
            "Subject": {"Data": subj},
            "Body": {"Html": {"Data": body_html}},
        },
    )


def _remediate_iam(principal, remediation):
    if not principal or principal == "UNKNOWN":
        remediation["actionsTaken"].append("SKIPPED: could not determine principal")
        return

    try:
        keys = iam.list_access_keys(UserName=principal)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] == "Active":
                iam.update_access_key(
                    UserName=principal,
                    AccessKeyId=key["AccessKeyId"],
                    Status="Inactive",
                )
                remediation["actionsTaken"].append(
                    f"DEACTIVATED_KEY: {key['AccessKeyId']} for user {principal}"
                )
                logger.info("Deactivated key %s for %s", key["AccessKeyId"], principal)
    except iam.exceptions.NoSuchEntityException:
        remediation["actionsTaken"].append(f"NO_KEYS_FOUND for user {principal}")

    try:
        iam.attach_user_policy(UserName=principal, PolicyArn=DENY_POLICY_ARN)
        remediation["actionsTaken"].append(f"ATTACHED_DENY_POLICY to user {principal}")
        logger.info("Attached DenyAll to %s", principal)
    except Exception as e:
        remediation["actionsTaken"].append(f"DENY_POLICY_FAILED: {e!s}")


def _remediate_ec2(event, remediation):
    response_elements = event.get("responseElements", {})
    instances_set = response_elements.get("instancesSet", {})
    items = instances_set.get("items", [])

    if not items:
        remediation["actionsTaken"].append("NO_INSTANCE_ID in event responseElements")
        return

    for item in items:
        instance_id = item.get("instanceId")
        if not instance_id:
            continue
        try:
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[QUARANTINE_SG_ID],
            )
            remediation["actionsTaken"].append(
                f"ISOLATED_INSTANCE: {instance_id} → quarantine SG {QUARANTINE_SG_ID}"
            )
            logger.info("Isolated instance %s", instance_id)
        except Exception as e:
            remediation["actionsTaken"].append(
                f"EC2_ISOLATE_FAILED {instance_id}: {e!s}"
            )
