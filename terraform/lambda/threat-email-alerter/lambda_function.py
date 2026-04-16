import boto3
import os

ses = boto3.client("ses", region_name="us-east-1")

FROM_EMAIL = os.environ.get("SES_FROM_EMAIL", "")
TO_EMAIL = os.environ.get("SES_TO_EMAIL", "")

SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH":     "#FF6600",
    "MEDIUM":   "#FFA500",
    "LOW":      "#008000",
    "UNKNOWN":  "#808080",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️",
    "MEDIUM":   "🔔",
    "LOW":      "ℹ️",
    "UNKNOWN":  "❓",
}


def build_html_email(event: dict, analysis: dict) -> str:
    severity = event.get("severity", "UNKNOWN")
    color = SEVERITY_COLORS.get(severity, "#808080")
    emoji = SEVERITY_EMOJI.get(severity, "❓")
    threat_score = event.get("threatScore", 0)
    indicators = analysis.get("indicators", [])
    indicators_html = "".join(f"<li>{i}</li>" for i in indicators)

    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body {{
      font-family: Arial, sans-serif;
      background-color: #f4f4f4;
      margin: 0;
      padding: 20px;
    }}
    .container {{
      max-width: 680px;
      margin: 0 auto;
      background-color: #ffffff;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }}
    .header {{
      background-color: {color};
      color: white;
      padding: 24px 32px;
    }}
    .header h1 {{
      margin: 0;
      font-size: 22px;
    }}
    .header p {{
      margin: 6px 0 0;
      opacity: 0.9;
      font-size: 14px;
    }}
    .score-badge {{
      display: inline-block;
      background: rgba(255,255,255,0.25);
      border-radius: 20px;
      padding: 4px 14px;
      font-size: 18px;
      font-weight: bold;
      margin-top: 10px;
    }}
    .body {{
      padding: 28px 32px;
    }}
    .section {{
      margin-bottom: 24px;
    }}
    .section-title {{
      font-size: 11px;
      font-weight: bold;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #888;
      margin-bottom: 6px;
    }}
    .section-value {{
      font-size: 15px;
      color: #222;
      line-height: 1.5;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      background: #f9f9f9;
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 24px;
    }}
    .meta-item .label {{
      font-size: 11px;
      color: #999;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .meta-item .value {{
      font-size: 14px;
      color: #333;
      font-weight: 500;
      word-break: break-all;
    }}
    .indicators {{
      background: #fff8f0;
      border-left: 3px solid {color};
      padding: 12px 16px;
      border-radius: 0 6px 6px 0;
    }}
    .indicators ul {{
      margin: 6px 0 0;
      padding-left: 18px;
    }}
    .indicators li {{
      font-size: 14px;
      color: #444;
      margin-bottom: 4px;
    }}
    .action-box {{
      background: #f0f7ff;
      border: 1px solid #cce0ff;
      border-radius: 6px;
      padding: 14px 18px;
      font-size: 14px;
      color: #1a4f8a;
    }}
    .footer {{
      background: #f4f4f4;
      padding: 16px 32px;
      font-size: 12px;
      color: #aaa;
      text-align: center;
    }}
  </style>
</head>
<body>
  <div class="container">

    <div class="header">
      <h1>{emoji} Threat Detected — {event.get("eventName", "Unknown Event")}</h1>
      <p>{event.get("eventTime", "")} &nbsp;|&nbsp; {event.get("awsRegion", "")}</p>
      <div class="score-badge">Threat Score: {threat_score} / 10 &nbsp;·&nbsp; {severity}</div>
    </div>

    <div class="body">

      <div class="section">
        <div class="section-title">Summary</div>
        <div class="section-value">{analysis.get("summary", "No summary available.")}</div>
      </div>

      <div class="meta-grid">
        <div class="meta-item">
          <div class="label">Source IP</div>
          <div class="value">{event.get("sourceIPAddress", "unknown")}</div>
        </div>
        <div class="meta-item">
          <div class="label">User ARN</div>
          <div class="value">{event.get("userArn", "unknown")}</div>
        </div>
        <div class="meta-item">
          <div class="label">User Type</div>
          <div class="value">{event.get("userType", "unknown")}</div>
        </div>
        <div class="meta-item">
          <div class="label">Event ID</div>
          <div class="value">{event.get("eventId", "unknown")}</div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Reasoning</div>
        <div class="section-value">{analysis.get("reasoning", "No reasoning provided.")}</div>
      </div>

      <div class="section">
        <div class="section-title">Threat Indicators</div>
        <div class="indicators">
          <ul>{indicators_html}</ul>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Recommended Action</div>
        <div class="action-box">
          {analysis.get("recommendedAction", "No recommendation available.")}
        </div>
      </div>

    </div>

    <div class="footer">
      AI-Powered Threat Detection Pipeline &nbsp;·&nbsp; Amazon Bedrock + AWS Step Functions
    </div>

  </div>
</body>
</html>
"""


def lambda_handler(event, context):
    """
    Receives an analyzed threat event and sends a formatted HTML
    email via SES. Only fires for threat scores >= 7.
    """
    threat_score = event.get("threatScore", 0)
    analysis = event.get("analysis", {})
    severity = event.get("severity", "UNKNOWN")

    # Only email on high-severity threats
    if threat_score < 7:
        return {
            "statusCode": 200,
            "emailSent": False,
            "reason": f"Score {threat_score} below threshold",
        }

    if not FROM_EMAIL or not TO_EMAIL:
        raise ValueError("SES_FROM_EMAIL and SES_TO_EMAIL environment variables must be set")

    subject = (
        f"[{severity}] Threat Detected — "
        f"{event.get('eventName', 'Unknown')} "
        f"(Score: {threat_score}/10)"
    )

    html_body = build_html_email(event, analysis)

    # Plain text fallback for email clients that don't render HTML
    text_body = f"""
THREAT DETECTED — {severity} (Score: {threat_score}/10)

Event:    {event.get("eventName", "")}
Time:     {event.get("eventTime", "")}
Region:   {event.get("awsRegion", "")}
Source IP: {event.get("sourceIPAddress", "")}
User:     {event.get("userArn", "")}

Summary:
{analysis.get("summary", "")}

Reasoning:
{analysis.get("reasoning", "")}

Recommended Action:
{analysis.get("recommendedAction", "")}

Indicators:
{chr(10).join("- " + i for i in analysis.get("indicators", []))}

Event ID: {event.get("eventId", "")}
"""

    ses.send_email(
        Source=FROM_EMAIL,
        Destination={"ToAddresses": [TO_EMAIL]},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {
                "Text": {"Data": text_body, "Charset": "UTF-8"},
                "Html": {"Data": html_body, "Charset": "UTF-8"},
            },
        },
    )

    return {
        "statusCode": 200,
        "emailSent": True,
        "subject": subject,
        "severity": severity,
        "threatScore": threat_score,
    }
