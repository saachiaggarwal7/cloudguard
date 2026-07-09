from Modules.iam_auditor import scan_iam_users
from Modules.ec2_scanner import ec2_scanner
from Modules.s3_scanner import s3_scanner
from Modules.security_group_scanner import security_group_scanner
from Modules.report_generator import generate_report
from Modules.vpc_scanner import vpc_scanner
from Modules.cloudtrail_scanner import cloudtrail_scanner

import boto3

findings=[]

def create_session():
    print("\nSelect Region")
    print("1. Default Region")
    print("2. Select Region")
    print("3. Scan All Regions")
    try:
        choice=int(input("Enter choice:"))
    except ValueError:
        print("Please enter a valid number.")
        return None

    if choice==1:
        return [boto3.Session()]
    elif choice==2:
        input_region=input("Enter AWS region:").strip()
        ec2_client=boto3.client("ec2")
        regions=ec2_client.describe_regions()['Regions']
        for region in regions:
            if input_region == region['RegionName']:
                try:
                    return [boto3.Session(region_name=input_region)]
                except Exception:
                    print("Invalid region.")
                    return None
        print("Region not available.")
        return None
    elif choice==3:
        sessions=[]
        ec2_client=boto3.client("ec2")
        regions=ec2_client.describe_regions()["Regions"]
        for region in regions:
                sessions.append(boto3.Session(region_name=region["RegionName"]))
        return sessions
    else:
        print("Invalid choice.")
        return None


def display_finding(findings):
    if not findings:
        print("No vulnerability found")
        return
    for finding in findings:
            print("="*60)
            for key,value in finding.items():
                print(f"{key} : {value}")

while(True):
    print("="*60)
    print(" "*20+"CLOUD GUARD")
    print("="*60)
    print("\n1. Scan Everything \n2. Scan IAM \n3. Scan S3 \n4. Scan EC2 \n5. Scan Security Groups \n6. VPC Scanner \n7. CloudTrail Scanner \n8. Generate Report \n9. Exit")
    try:
        choice=int(input("Enter choice:"))
    except ValueError:
        print("Please enter a valid number.")
        continue
    if choice==1:
        findings=[]
        sessions=create_session()
        if sessions is None:
            continue
        findings.extend(scan_iam_users(sessions[0]))
        findings.extend(s3_scanner(sessions[0]))
        for session in sessions:
            findings.extend(ec2_scanner(session))
            findings.extend(security_group_scanner(session))
        display_finding(findings)
    elif choice==2:
        findings=[]
        sessions=create_session()
        if sessions is None:
            continue
        findings.extend(scan_iam_users(sessions[0]))
        display_finding(findings)
    elif choice==3:
        findings=[]
        sessions=create_session()
        if sessions is None:
            continue
        findings.extend(s3_scanner(sessions[0]))
        display_finding(findings)
    elif choice==4:
        findings=[]
        sessions=create_session()
        if sessions is None:
            continue
        for session in sessions:
            findings.extend(ec2_scanner(session))
        display_finding(findings)
    elif choice==5:
        findings=[]
        sessions=create_session()
        if sessions is None:
            continue
        for session in sessions:
            findings.extend(security_group_scanner(session))
        display_finding(findings)
    elif choice==6:
        findings=[]
        sessions=create_session()
        if sessions is None:
            continue
        for session in sessions:
            findings.extend(vpc_scanner(session))
        display_finding(findings)
    elif choice==7:
        findings=[]
        sessions=create_session()
        if sessions is None:
            continue
        for session in sessions:
            findings.extend(cloudtrail_scanner(session))
        display_finding(findings)
    elif choice==8:
        if findings:
            generate_report(findings)
            print("Report generated successfully!")
        else:
            print("No scan results available. Please run a scan first.")
    elif choice==9:
        print("Thank you for using CloudGuard!")
        break
    else:
        print("Please enter a number between 1 and 8.")





