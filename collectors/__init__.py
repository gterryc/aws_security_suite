from collectors import (
    iam_collector,
    s3_collector,
    ec2_collector,
    rds_collector,
    guardduty_collector,
    cloudwatch_collector,
    vpc_collector,
)

COLLECTORS = {
    "iam":        iam_collector.collect,
    "s3":         s3_collector.collect,
    "ec2":        ec2_collector.collect,
    "rds":        rds_collector.collect,
    "guardduty":  guardduty_collector.collect,
    "cloudwatch": cloudwatch_collector.collect,
    "vpc":        vpc_collector.collect,
}