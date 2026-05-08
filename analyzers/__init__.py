from analyzers import (
    iam_analyzer,
    s3_analyzer,
    ec2_analyzer,
    rds_analyzer,
    guardduty_analyzer,
    cloudwatch_analyzer,
    vpc_analyzer,
)

ANALYZERS = {
    "iam":        iam_analyzer.analyze,
    "s3":         s3_analyzer.analyze,
    "ec2":        ec2_analyzer.analyze,
    "rds":        rds_analyzer.analyze,
    "guardduty":  guardduty_analyzer.analyze,
    "cloudwatch": cloudwatch_analyzer.analyze,
    "vpc":        vpc_analyzer.analyze,
}