output "insecure_user_no_mfa_arn" { value = aws_iam_user.no_mfa.arn }
output "insecure_user_direct_policy" { value = aws_iam_user.direct_policy.arn }
output "insecure_policy_star_star" { value = aws_iam_policy.star_star.arn }
output "insecure_group_empty" { value = aws_iam_group.empty.name }
output "secure_user_arn" { value = aws_iam_user.secure.arn }
output "secure_role_support_arn" { value = aws_iam_role.support.arn }
output "access_analyzer_arn" { value = aws_accessanalyzer_analyzer.main.arn }
