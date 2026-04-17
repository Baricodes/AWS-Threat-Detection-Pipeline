# threat-record-writer; composite key + ttl attribute for automatic item expiry.
resource "aws_dynamodb_table" "threat_detection_events" {
  name         = "ThreatDetectionEvents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "eventId"
  range_key    = "timestamp"

  attribute {
    name = "eventId"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}
