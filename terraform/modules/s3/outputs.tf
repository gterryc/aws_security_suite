output "insecure_bucket_no_encryption" { value = aws_s3_bucket.no_encryption.id }
output "insecure_bucket_no_block" { value = aws_s3_bucket.no_public_block.id }
output "insecure_bucket_no_logging" { value = aws_s3_bucket.no_logging.id }
output "insecure_bucket_no_versioning" { value = aws_s3_bucket.no_versioning.id }
output "secure_bucket" { value = aws_s3_bucket.secure.id }
output "log_bucket" { value = aws_s3_bucket.logs.id }
