output "insecure_db_id" { value = aws_db_instance.insecure.identifier }
output "insecure_db_arn" { value = aws_db_instance.insecure.arn }
output "secure_db_id" { value = aws_db_instance.secure.identifier }
output "secure_db_arn" { value = aws_db_instance.secure.arn }
output "public_snapshot_id" { value = aws_db_snapshot.public_snap.db_snapshot_identifier }
