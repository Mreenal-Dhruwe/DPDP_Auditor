resource "aws_cloudwatch_log_group" "api" {
  name              = "/shop/api"
  retention_in_days = 30
}
