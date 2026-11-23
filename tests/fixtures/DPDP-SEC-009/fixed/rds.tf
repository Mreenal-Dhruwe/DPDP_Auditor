resource "aws_db_instance" "orders" {
  engine                  = "mysql"
  instance_class          = "db.t4g.small"
  backup_retention_period = 7
}

resource "google_sql_database_instance" "users" {
  database_version = "POSTGRES_16"
  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled = true
    }
  }
}
