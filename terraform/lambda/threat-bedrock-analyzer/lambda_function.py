"""Map iterator task: Bedrock Claude Haiku → JSON score + analysis.

Output shape must satisfy Step Functions MergeAnalysis
($.analysisResult.result.*).
"""
import json

import boto3

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"

THREAT_ANALYSIS_PROMPT = (
    "You are a senior cloud incident responder. Score this single AWS "
    "CloudTrail event for automated SOAR: be decisive, consistent, and "
    'conservative about calling benign admin work "critical".\n\n'
    "Event Details:\n"
    "- Event Name: {event_name}\n"
    "- Source IP: {source_ip}\n"
    "- User ARN: {user_arn}\n"
    "- User Type: {user_type}\n"
    "- Region: {aws_region}\n"
    "- Error Code: {error_code}\n"
    "- Request Parameters: {request_params}\n"
    "- User Agent: {user_agent}\n"
    "\n"
    "Scoring rules (apply in order):\n"
    "1) Outcome: If error_code shows the API failed (e.g. AccessDenied, "
    "UnauthorizedOperation) and there is no sign of partial success, cap "
    "the score at 6 unless the attempt itself is a high-risk action against "
    "a highly sensitive target (then max 8).\n"
    "2) Privilege & persistence: These are inherently high impact when "
    "successful: CreateAccessKey, CreateLoginProfile, Attach*/Put* on IAM "
    "users/roles/groups, CreateUser + immediate admin attachment, policy "
    "changes broadening admin paths, backdoor security group rules, public "
    "resource policies, DeleteTrail/StopLogging, disabling guardrails. If "
    "successful and the target is another principal (not self-service "
    "password reset), or the user/resource name suggests "
    "break-glass/admin/root-equivalent, treat as 9–10 unless strong "
    "evidence it is routine approved automation (named service role, "
    "expected user agent pattern you would document as normal for the "
    "org—assume unknown unless obvious).\n"
    "3) Lateral movement / cred abuse signals: Unfamiliar IP + CLI/SDK + "
    "IAM mutation for another user, or key/session creation for "
    "privileged-looking accounts, should be 9–10, not 8, when successful.\n"
    "4) Separation of bands: 7 = suspicious context but plausible ops or "
    "incomplete signal. 8 = likely malicious or policy violation but "
    "contained blast radius or missing confirmation. 9–10 = credible "
    "account compromise / persistence / privilege escalation / cover-up "
    "logging — warrants immediate containment.\n"
    "5) Severity mapping: scores 1–3 LOW, 4–6 MEDIUM, 7–8 HIGH, 9–10 "
    "CRITICAL.\n"
    "\n"
    "Respond ONLY with a valid JSON object in this exact format (no other "
    "text):\n"
    "{{\n"
    '  "threatScore": <integer 1-10>,\n'
    '  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",\n'
    '  "summary": "<one sentence summary of what happened>",\n'
    '  "reasoning": "<2-3 sentences explaining why this is or is not a threat>",\n'
    '  "indicators": ["<indicator 1>", "<indicator 2>"],\n'
    '  "recommendedAction": "<one specific recommended action>"\n'
    "}}"
)


def lambda_handler(event, context):
    # Map item is the enriched event; direct invokes may use top-level fields.
    src = event.get("enrichedEvent") or event
    user_identity = src.get("userIdentity", {})

    prompt = THREAT_ANALYSIS_PROMPT.format(
        event_name=src.get("eventName", ""),
        source_ip=src.get("sourceIPAddress", ""),
        user_arn=user_identity.get("arn", ""),
        user_type=user_identity.get("type", ""),
        aws_region=src.get("awsRegion", "us-east-1"),
        error_code=src.get("errorCode", "none"),
        request_params=json.dumps(src.get("requestParameters", {})),
        user_agent=src.get("userAgent", ""),
    )

    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 512,
            "messages": [{"role": "user", "content": prompt}],
        }
    )

    try:
        response = bedrock.invoke_model(
            modelId=MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=body,
        )

        response_body = json.loads(response["body"].read())
        analysis_text = response_body["content"][0]["text"].strip()

        if analysis_text.startswith("```"):
            analysis_text = analysis_text.split("```")[1]
            if analysis_text.startswith("json"):
                analysis_text = analysis_text[4:]

        analysis = json.loads(analysis_text)

    except json.JSONDecodeError as e:
        analysis = {
            "threatScore": 5,
            "severity": "MEDIUM",
            "summary": "Analysis parsing failed — manual review required",
            "reasoning": f"Bedrock returned unparseable response: {e!s}",
            "indicators": ["parse_error"],
            "recommendedAction": "Review raw CloudTrail event manually",
        }

    # Keys at root for MergeAnalysis / Choice on $.threatScore (stable JSONPath).
    return {
        "accountId": src.get("accountId", ""),
        "awsRegion": src.get("awsRegion", "us-east-1"),
        "eventName": src.get("eventName", ""),
        "eventTime": src.get("eventTime", ""),
        "eventSource": src.get("eventSource", ""),
        "sourceIPAddress": src.get("sourceIPAddress", ""),
        "userIdentity": user_identity,
        "responseElements": src.get("responseElements", {}),
        "requestParameters": src.get("requestParameters", {}),
        "userAgent": src.get("userAgent", ""),
        "errorCode": src.get("errorCode", ""),
        "errorMessage": src.get("errorMessage", ""),
        "threatId": src.get("threatId", ""),
        "eventId": src.get("eventId", ""),
        "originalEventId": src.get("originalEventId", ""),
        "userArn": src.get("userArn", user_identity.get("arn", "")),
        "userType": src.get("userType", user_identity.get("type", "")),
        "ingestedAt": src.get("ingestedAt", ""),
        "rawEvent": src.get("rawEvent", ""),
        "analysis": analysis,
        "threatScore": analysis.get("threatScore", 0),
        "severity": analysis.get("severity", "UNKNOWN"),
    }
