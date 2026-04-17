import json
import boto3
import os

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

THREAT_ANALYSIS_PROMPT = """You are a senior cloud incident responder. Score this single AWS CloudTrail event for automated SOAR: be decisive, consistent, and conservative about calling benign admin work "critical".

Event Details:
- Event Name: {event_name}
- Source IP: {source_ip}
- User ARN: {user_arn}
- User Type: {user_type}
- Region: {aws_region}
- Error Code: {error_code}
- Request Parameters: {request_params}
- User Agent: {user_agent}

Scoring rules (apply in order):
1) Outcome: If error_code shows the API failed (e.g. AccessDenied, UnauthorizedOperation) and there is no sign of partial success, cap the score at 6 unless the attempt itself is a high-risk action against a highly sensitive target (then max 8).
2) Privilege & persistence: These are inherently high impact when successful: CreateAccessKey, CreateLoginProfile, Attach*/Put* on IAM users/roles/groups, CreateUser + immediate admin attachment, policy changes broadening admin paths, backdoor security group rules, public resource policies, DeleteTrail/StopLogging, disabling guardrails. If successful and the target is another principal (not self-service password reset), or the user/resource name suggests break-glass/admin/root-equivalent, treat as 9–10 unless strong evidence it is routine approved automation (named service role, expected user agent pattern you would document as normal for the org—assume unknown unless obvious).
3) Lateral movement / cred abuse signals: Unfamiliar IP + CLI/SDK + IAM mutation for another user, or key/session creation for privileged-looking accounts, should be 9–10, not 8, when successful.
4) Separation of bands: 7 = suspicious context but plausible ops or incomplete signal. 8 = likely malicious or policy violation but contained blast radius or missing confirmation. 9–10 = credible account compromise / persistence / privilege escalation / cover-up logging — warrants immediate containment.
5) Severity mapping: scores 1–3 LOW, 4–6 MEDIUM, 7–8 HIGH, 9–10 CRITICAL.

Respond ONLY with a valid JSON object in this exact format (no other text):
{{
  "threatScore": <integer 1-10>,
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<one sentence summary of what happened>",
  "reasoning": "<2-3 sentences explaining why this is or isn't a threat>",
  "indicators": ["<indicator 1>", "<indicator 2>"],
  "recommendedAction": "<one specific recommended action>"
}}"""


def lambda_handler(event, context):
    # Step Functions passes the map item under Payload.enrichedEvent
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

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 512,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    })

    try:
        response = bedrock.invoke_model(
            modelId="anthropic.claude-3-haiku-20240307-v1:0",
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
            "reasoning": f"Bedrock returned unparseable response: {str(e)}",
            "indicators": ["parse_error"],
            "recommendedAction": "Review raw CloudTrail event manually",
        }

    # Echo fields MergeAnalysis reads from $.analysisResult.result so paths
    # always exist (CloudTrail-shaped tests may omit keys the enricher adds).
    return {
        "accountId":         src.get("accountId", ""),
        "awsRegion":         src.get("awsRegion", "us-east-1"),
        "eventName":         src.get("eventName", ""),
        "eventTime":         src.get("eventTime", ""),
        "eventSource":       src.get("eventSource", ""),
        "sourceIPAddress":   src.get("sourceIPAddress", ""),
        "userIdentity":      user_identity,
        "responseElements":  src.get("responseElements", {}),
        "requestParameters": src.get("requestParameters", {}),
        "userAgent":         src.get("userAgent", ""),
        "errorCode":         src.get("errorCode", ""),
        "errorMessage":      src.get("errorMessage", ""),
        "threatId":          src.get("threatId", ""),
        "eventId":           src.get("eventId", ""),
        "originalEventId":   src.get("originalEventId", ""),
        "userArn":           src.get("userArn", user_identity.get("arn", "")),
        "userType":          src.get("userType", user_identity.get("type", "")),
        "ingestedAt":        src.get("ingestedAt", ""),
        "rawEvent":          src.get("rawEvent", ""),

        "analysis":    analysis,
        "threatScore": analysis.get("threatScore", 0),
        "severity":    analysis.get("severity", "UNKNOWN"),
    }