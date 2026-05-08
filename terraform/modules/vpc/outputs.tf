output "vpc_secure_id" { value = aws_vpc.secure.id }
output "vpc_insecure_id" { value = aws_vpc.insecure.id }
output "public_subnet_id" { value = aws_subnet.public.id }
output "private_subnet_id" { value = aws_subnet.private_a.id }
output "private_subnet_ids" { value = [aws_subnet.private_a.id, aws_subnet.private_b.id] }
output "public_subnet_ids" { value = [aws_subnet.public.id] }
output "insecure_subnet_id" { value = aws_subnet.insecure_public.id }
output "insecure_subnet_ids" { value = [aws_subnet.insecure_public.id, aws_subnet.insecure_public_b.id] }