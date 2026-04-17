# VPC hosting quarantine_sg (required for EC2 modify-instance-attribute security group IDs).
resource "aws_vpc" "default_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  instance_tenancy     = "default"

  tags = {
    Name = "default-vpc"
  }
}
