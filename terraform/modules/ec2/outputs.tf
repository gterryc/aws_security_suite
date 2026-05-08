output "insecure_instance_id" { value = aws_instance.insecure_no_imdsv2.id }
output "secure_instance_id" { value = aws_instance.secure.id }
output "insecure_sg_id" { value = aws_security_group.open_ssh_rdp.id }
output "secure_sg_id" { value = aws_security_group.secure.id }
output "unencrypted_volume_id" { value = aws_ebs_volume.unencrypted.id }
output "public_snapshot_id" { value = aws_ebs_snapshot.public_snap.id }
