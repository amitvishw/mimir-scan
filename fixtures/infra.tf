provider "aws" {
  region = "us-east-1"
}

# S3 bucket with no encryption, public access
resource "aws_s3_bucket" "data" {
  bucket = "my-public-data-bucket"
  acl    = "public-read"
}

# Security group allowing all inbound traffic
resource "aws_security_group" "allow_all" {
  name = "allow_all"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS with no encryption
resource "aws_db_instance" "default" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = "admin123"
  publicly_accessible = true
  storage_encrypted   = false
}
