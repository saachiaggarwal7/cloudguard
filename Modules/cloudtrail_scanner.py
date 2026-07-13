import boto3

def cloudtrail_scanner(session):
    findings=[]
    region=session.region_name
    cloudtrail_client=session.client("cloudtrail")
    response=cloudtrail_client.describe_trails()
    trails=response['trailList']

    #detects if CloudTrail is not enabled
    if not trails:
        finding = {
            "rule_id": "CG-CT-001",
            "service": "CloudTrail",
            "region": region,
            "resource": "AWS Account",
            "severity": "HIGH",
            "finding": "CloudTrail is not configured.",
            "recommendation": "Create and enable a CloudTrail trail to record AWS API activity."
        }
        findings.append(finding)
    else:
        for trail in trails:

            #checking if multi region trail is enabled or not
            if not trail["IsMultiRegionTrail"]:
                finding = {
                    "rule_id": "CG-CT-002",
                    "service": "CloudTrail",
                    "region": region,
                    "resource": trail["Name"],
                    "trail_name": trail["Name"],
                    "severity": "MEDIUM",
                    "finding": "CloudTrail is not configured as a multi-region trail.",
                    "recommendation": "Enable multi-region logging to capture API activity across all AWS regions."
                }
                findings.append(finding)

            #checks if log file validation is enabled
            if not trail.get('LogFileValidationEnabled'):
                finding = {
                    "rule_id": "CG-CT-003",
                    "service": "CloudTrail",
                    "region": region,
                    "resource": trail["Name"],
                    "trail_name": trail["Name"],
                    "severity": "MEDIUM",
                    "finding": "CloudTrail log file validation is disabled.",
                    "recommendation": "Enable log file validation to detect unauthorized modification of CloudTrail logs."
                }
                findings.append(finding)

            # checks cloudwatch logs integration
            if not trail.get("CloudWatchLogsLogGroupArn"):
                finding = {
                    "rule_id": "CG-CT-004",
                    "service": "CloudTrail",
                    "region": region,
                    "resource": trail["Name"],
                    "trail_name": trail["Name"],
                    "severity": "MEDIUM",
                    "finding": "CloudTrail is not integrated with CloudWatch Logs.",
                    "recommendation": "Integrate CloudTrail with CloudWatch Logs to enable real-time monitoring, alerting, and log analysis."
                }
                findings.append(finding)
            
            #checks  Customer-managed KMS encryption 
            if not trail.get("KmsKeyId"):
                finding = {
                    "rule_id": "CG-CT-005",
                    "service": "CloudTrail",
                    "region": region,
                    "resource": trail["Name"],
                    "severity": "MEDIUM",
                    "finding": "CloudTrail is not encrypted with a customer-managed KMS key.",
                    "recommendation": "Configure a customer-managed AWS KMS key to encrypt CloudTrail logs."
                }
                findings.append(finding)
    if not findings:
        print("No CloudTrail vulnerability found.")
    return findings