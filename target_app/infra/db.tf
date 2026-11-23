# Database for the demo lending app. Answer key: ../../ground_truth.yml
provider "aws" {
  region = "ap-south-1" # Mumbai
}

resource "aws_db_instance" "lending" {
  identifier              = "lending-db"
  engine                  = "postgres"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  username                = "lending"
  password                = var.db_password
  storage_encrypted       = true
  backup_retention_period = 14
}

variable "db_password" {
  type      = string
  sensitive = true
}
