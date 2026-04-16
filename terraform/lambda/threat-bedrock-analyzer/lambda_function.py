import json
import boto3
import os

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

THREAT_ANALYSIS_PROMPT = """You are a cloud security analyst. Analyze the following AWS CloudTrail event and assess the threat level.

Event Details:
- Event Name: {event_name}
- Source IP: {source_ip}
- User ARN: {user_arn}
- User Type: {user_type}
- Region: {aws_region}
- Error Code: {error_code}
- Request Parameters: {request_params}
- User Agent: {user_agent}

Respond ONLY with a valid JSON object in this exact format (no other text):
{{
  "threatScore": <integer 1-10>,
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<one sentence summary of what happened>",
  "reasoning": "<2-3 sentences explaining why this is or isn't a threat>",
  "indicators": ["<indicator 1>", "<indicator 2>"],
  "recommendedAction": "<one specific recommended action>"
}}

Scoring guide:
1-3: Normal operations, expected behavior
4-6: Unusual but potentially legitimate, worth monitoring  
7-8: Highly suspicious, likely malicious
9-10: Critical threat, immediate action required"""


def lambda_handler(event, context):
    """
    Takes an enriched CloudTrail event, calls Bedrock Claude Haiku
    to analyze it, and returns a structured threat assessment.
    """
    enriched_event = event.get("enrichedEvent", event)

    prompt = THREAT_ANALYSIS_PROMPT.format(
        event_name=enriched_event.get("eventName", ""),
        source_ip=enriched_event.get("sourceIPAddress", ""),
        user_arn=enriched_event.get("userArn", ""),
        user_type=enriched_event.get("userType", ""),
        aws_region=enriched_event.get("awsRegion", ""),
        error_code=enriched_event.get("errorCode", "none"),
        request_params=enriched_event.get("requestParameters", "{}"),
        user_agent=enriched_event.get("userAgent", ""),
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
            modelId="anthropic.claude-haiku-20240307-v1:0",
            contentType="application/json",
            accept="application/json",
            body=body,
        )

        response_body = json.loads(response["body"].read())
        analysis_text = response_body["content"][0]["text"].strip()

        # Strip markdown code fences if present
        if analysis_text.startswith("```"):
            analysis_text = analysis_text.split("```")[1]
            if analysis_text.startswith("json"):
                analysis_text = analysis_text[4:]

        analysis = json.loads(analysis_text)

    except json.JSONDecodeError as e:
        # Fallback if Bedrock response isn't clean JSON
        analysis = {
            "threatScore": 5,
            "severity": "MEDIUM",
            "summary": "Analysis parsing failed — manual review required",
            "reasoning": f"Bedrock returned unparseable response: {str(e)}",
            "indicators": ["parse_error"],
            "recommendedAction": "Review raw CloudTrail event manually",
        }

    return {
        **enriched_event,
        "analysis": analysis,
        "threatScore": analysis.get("threatScore", 0),
        "severity": analysis.get("severity", "UNKNOWN"),
    }
