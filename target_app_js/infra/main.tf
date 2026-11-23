# Infrastructure for the demo shop. Answer key: ../../ground_truth_js.yml
provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "shop" {
  identifier              = "shop-db"
  engine                  = "postgres"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  username                = "shop"
  password                = var.db_password
  storage_encrypted       = true
  backup_retention_period = 0
}

variable "db_password" {
  type      = string
  sensitive = true
}
