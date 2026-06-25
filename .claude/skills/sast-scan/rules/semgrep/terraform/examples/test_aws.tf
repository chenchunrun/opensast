# Terraform security rule test fixtures

# --- terraform.aws.s3-bucket-public-acl ---

resource "aws_s3_bucket" "bad_public" {
  bucket = "my-public-bucket"
  # ruleid: terraform.aws.s3-bucket-public-acl
  acl = "public-read"
}

resource "aws_s3_bucket" "bad_public_write" {
  bucket = "my-public-bucket"
  # ruleid: terraform.aws.s3-bucket-public-acl
  acl = "public-read-write"
}

resource "aws_s3_bucket" "safe" {
  bucket = "my-private-bucket"
  # ok: terraform.aws.s3-bucket-public-acl
  acl = "private"
}

# --- terraform.aws.s3-bucket-no-encryption ---

resource "aws_s3_bucket" "no_encrypt" {
  # ruleid: terraform.aws.s3-bucket-no-encryption
  bucket = "unencrypted-bucket"
}

resource "aws_s3_bucket" "encrypted" {
  bucket = "encrypted-bucket"
  # ok: terraform.aws.s3-bucket-no-encryption
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

# --- terraform.aws.security-group-open-world ---

resource "aws_security_group" "open" {
  name = "open-sg"
  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    # ruleid: terraform.aws.security-group-open-world
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "restricted" {
  name = "restricted-sg"
  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    # ok: terraform.aws.security-group-open-world
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# --- terraform.aws.iam-policy-wildcard ---

resource "aws_iam_policy" "bad" {
  name = "too-broad"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      # ruleid: terraform.aws.iam-policy-wildcard
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "safe" {
  name = "least-privilege"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}

# --- terraform.aws.rds-public-access ---

resource "aws_db_instance" "bad" {
  # ruleid: terraform.aws.rds-public-access
  publicly_accessible = true
}

resource "aws_db_instance" "safe" {
  # ok: terraform.aws.rds-public-access
  publicly_accessible = false
}

# --- terraform.aws.ec2-imdsv1 ---

resource "aws_instance" "bad_imds" {
  metadata_options {
    # ruleid: terraform.aws.ec2-imdsv1
    http_tokens = "optional"
  }
}

resource "aws_instance" "safe_imds" {
  metadata_options {
    # ok: terraform.aws.ec2-imdsv1
    http_tokens = "required"
  }
}

# --- terraform.general.hardcoded-credentials ---

# ruleid: terraform.generic.provider-hardcoded-credentials
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ok: terraform.generic.provider-hardcoded-credentials
provider "aws" {
  region = "us-east-1"
}
