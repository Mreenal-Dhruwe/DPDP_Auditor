resource "aws_s3_bucket_acl" "kyc_docs" {
  bucket = aws_s3_bucket.kyc_docs.id
  acl    = "public-read"
}
