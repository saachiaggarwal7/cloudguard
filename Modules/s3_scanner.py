import boto3
import json
from botocore.exceptions import ClientError
def s3_scanner():
    findings=[]
    s3_client=boto3.client('s3')
    buckets=s3_client.list_buckets()['Buckets']
    for bucket in buckets:
        bucket_name=bucket['Name']

        #checking whether bhucket policy allows public access
        try:
           policies_str=s3_client.get_bucket_policy(Bucket=bucket_name)['Policy']
           policies=json.loads(policies_str)
           for statement in policies['Statement']:
                principal=statement.get('Principal')
                effect=statement.get('Effect')
                if effect =="Allow":
                   if principal=="*" :
                        finding={
                       "rule_id": "CG-S3-001",
                        "service": "S3",
                        "resource":bucket_name,
                        "severity": "HIGH",
                        "finding": "Bucket policy allows public access.",
                        "recommendation": "Remove public access or restrict access to specific AWS principals."
                        }
                        findings.append(finding)
                        break
                   elif isinstance(principal,dict):
                        if principal.get('AWS')=="*":
                                finding={
                                "rule_id": "CG-S3-001",
                                "service": "S3",
                                "resource":bucket_name,
                                "severity": "HIGH",
                                "finding": "Bucket policy allows public access.",
                                "recommendation": "Remove public access or restrict access to specific AWS principals."
                                }
                                findings.append(finding)
                                break                              
        except ClientError as e:
            error=e.response["Error"]["Code"]
            if error !="NoSuchBucketPolicy":
              print (f"Error scanning {bucket_name} : {error}")

        #Checking whether Block public is disabled or not
        try:
            public_access_block=s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
            if not all(public_access_block.values()):
                finding={
                    "rule_id": "CG-S3-002",
                    "service": "S3",
                    "resource":bucket_name,
                    "severity": "HIGH",
                    "finding": "One or more Block Public Access settings are disabled.",
                    "recommendation":"Enable all Block Public Access settings unless public access is intentionally required."
                    }
                findings.append(finding)
        except ClientError as e:
            error=e.response["Error"]["Code"]
            if error!="NoSuchPublicAccessBlockConfiguration":
                print(f"Error scanning {bucket_name} : {error}")

        #checking bucket's version
        versioning_status=s3_client.get_bucket_versioning(Bucket=bucket_name).get('Status')
        if versioning_status!="Enabled":
            finding= {
            "rule_id": "CG-S3-003",
            "service": "S3",
            "resource": bucket_name,
            "severity": "MEDIUM",
            "finding": "Bucket versioning is disabled.",
            "recommendation": "Enable versioning to protect against accidental deletion and ransomware."
            }
            findings.append(finding)
        
        #to check if s3 bucket logging is enabled or not
        s3_logging=s3_client.get_bucket_logging(Bucket=bucket_name)
        if not s3_logging.get("LoggingEnabled"):
            finding={
            "rule_id": "CG-S3-004",
            "service": "S3",
            "resource": bucket_name,
            "severity": "LOW",
            "finding":"Bucket access logging is disabled.",
            "recommendation": "Enable server access logging to improve auditing and forensic capabilities."
            }
            findings.append(finding)
        
        #to check if bucket has tagging or not
        try:
            s3_tagging=s3_client.get_bucket_tagging(Bucket=bucket_name)
        except ClientError as e:
            error=e.response["Error"]["Code"]
            if(error=="NoSuchTagSet"):
                finding={
                    "rule_id": "CG-S3-005",
                    "service": "S3",
                    "resource": bucket_name,
                    "severity": "LOW",
                    "finding":"Bucket has no tags",
                    "recommendation": "Add tags such as Owner, Environment, and Project for better governance."
                    }
                findings.append(finding)
            else:
                print(f"Error Occured: {error}")

    if not findings:
        print ("no vulnerability found")
    return findings