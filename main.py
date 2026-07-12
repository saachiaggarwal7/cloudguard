from Modules.iam_auditor import scan_iam_users
from Modules.ec2_scanner import ec2_scanner
from Modules.s3_scanner import s3_scanner
from Modules.security_group_scanner import security_group_scanner
from Modules.report_generator import generate_report
from Modules.vpc_scanner import vpc_scanner
from Modules.cloudtrail_scanner import cloudtrail_scanner

from Remediation.s3_remediation import (remediate_block_public_access,remediate_versioning)
from Remediation.ec2_remediation import (remediate_imdsv2,remediate_detailed_monitoring)
from Remediation.iam_remediation import (delete_access_key)
from Remediation.sg_remediation import delete_security_group
from Remediation.cloudtrail_remediation import remediate_multi_region
import boto3

remediation_map={
    "CG-IAM-007":delete_access_key,
    "CG-IAM-008":delete_access_key,
    "CG-S3-002":remediate_block_public_access,
    "CG-S3-003":remediate_versioning,
    "CG-EC2-002":remediate_imdsv2,
    "CG-EC2-003":remediate_detailed_monitoring,
    "CG-SG-004":delete_security_group,
    "CG-CT-002": remediate_multi_region,
}

manual_remediation={
    "CG-IAM-001": "Root MFA must be configured manually by an administrator. AWS does not support automatic MFA enrollment.",
    "CG-IAM-002": "User MFA requires the user to register and verify an MFA device manually.",
    "CG-IAM-003": "Removing AdministratorAccess may disrupt applications or administrative workflows. Review permissions manually.",
    "CG-IAM-004": "AdministratorAccess inherited through IAM Groups should be reviewed manually before modifying group permissions.",
    "CG-IAM-005": "Inline IAM policies require manual review to determine whether the permissions are necessary.",
    "CG-IAM-006": "Inline Group policies require manual review before removal or modification.",
    "CG-IAM-009": "Access key rotation is a multi-step process (create a new key, update applications, test, then remove the old key). Automatic rotation is not supported.",
    "CG-S3-001": "Bucket policies require manual review because removing them may break applications or public websites.",
    "CG-S3-004": "Bucket logging requires a destination logging bucket, so manual configuration is required.",
    "CG-S3-005": "Bucket tags depend on your organization's tagging strategy and must be added manually.",
    "CG-EC2-001": "Removing a public IP may interrupt SSH, web applications, or APIs. Review the network architecture before making changes.",
    "CG-EC2-004": "Encrypting an existing EBS volume requires creating an encrypted copy and replacing the volume. This cannot be safely automated.",
    "CG-SG-001":"Restrict SSH to your trusted public IP",
    "CG-SG-002":"Restrict RDP to trusted administrator IPs or use a VPN.",
    "CG-SG-003":"Replace the 'All Traffic' rule with only the required ports and trusted CIDR ranges."
}

scanner_map={
    "IAM":scan_iam_users,
    "EC2":ec2_scanner,
    "S3":s3_scanner,
    "SG":security_group_scanner,
    "VPC":vpc_scanner,
    "CT":cloudtrail_scanner
}

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

def display_summary(findings):
    severity_count={
        "CRITICAL":0,
        "HIGH":0,
        "MEDIUM":0,
        "LOW":0
    }

    for finding in findings:
        severity_count[finding["severity"]]+=1

    print("\n"+"="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Total Findings : {len(findings)}")
    print(f"Critical       : {severity_count['CRITICAL']}")
    print(f"High           : {severity_count['HIGH']}")
    print(f"Medium         : {severity_count['MEDIUM']}")
    print(f"Low            : {severity_count['LOW']}")   
    
def next_action_menu(findings):
    while True:
        print("\n"+"="*60)
        print("NEXT ACTION")
        print("="*60)
        print("1. Generate HTML Report")
        print("2. Remediate Findings")
        print("3. Return to Main Menu")

        try:
            choice=int(input("Enter choice:"))
        except ValueError:
            print("Please enter a valid number.")
            continue

        if choice==1:
            generate_report(findings)
            print("Report generated successfully.")
        elif choice==2:
            remediation_menu(findings)
        elif choice==3:
            break
        else:
            print("Invalid choice.")

def get_resource_identifier(selected):
    if selected["service"]=="EC2":
        return [selected["instance_id"]]
    if selected["service"]=="S3":
        return [selected["resource"]]
    if selected["service"]=="IAM":
       return [selected["resource"],selected["access_key"]]
    if selected["service"]=="Security Group":
        return [selected["group_id"]]


def remediation_menu(findings):
    while True:
        print("="*60)
        print(" "*20+f"AVAILABLE REMEDIATION  ({len(findings)} Findings)")
        print("="*60)
        if not findings:
            print("\nAll remediable findings have been addressed.")
            break
        num=1
        for finding in findings:
            if finding["rule_id"] in remediation_map:
                print(f"{num}.\nRule ID   : {finding["rule_id"]}\nResource  : {finding["resource"]}\nIssue     : {finding["finding"]}\nStatus    : ⚡Automatic")
            else:
                print(f"{num}.\nRule ID   : {finding["rule_id"]}\nResource  : {finding["resource"]}\nIssue     : {finding["finding"]}\nStatus    : 🔧Manual")
            num+=1
        print("0. Back")
        try:
            choice=int(input("Enter choice: "))
        except ValueError:
            print("Please enter a valid number.")
        if choice==0:
            break
        if choice<1 or choice>len(findings):
            print("Invalid choice.")
            continue
        selected=findings[choice-1]
        if selected["rule_id"] in manual_remediation:
            print("\nAutomatic remediation is not available.\n")
            print("Reason:")
            print(manual_remediation[selected["rule_id"]])
            continue
        print("\nYou are about to remediate:")
        print(f"Rule ID : {selected['rule_id']}")
        print(f"Resource: {selected['resource']}")
        confirm = input("Proceed? (Y/N): ").strip().upper()
        if confirm != "Y":
            continue
        region=selected["region"]
        if region=="Global":
            session=boto3.Session()
        else:
            session=boto3.Session(region_name=region)
        function=remediation_map[selected["rule_id"]]
        args=get_resource_identifier(selected)
        success=function(session,*args)
        if success:
            print("\n✓ Remediation completed successfully.")
            findings.remove(selected)
        else:
            print("\n✗ Remediation failed.")
    


def show_result(findings):
        display_finding(findings)
        display_summary(findings)
        if findings:
            next_action_menu(findings)     


def run_region_scanner(scanner):
    findings=[]
    sessions=create_session()
    if sessions is None:
        return
    for session in sessions:
        findings.extend(scanner(session))
    print("\nScanning completed successfully.\n")
    show_result(findings)  

def run_global_scanner(scanner):
    findings=[]
    sessions=create_session()
    if sessions is None:
        return
    findings.extend(scanner(sessions[0]))
    show_result(findings)



while(True):
    print("="*60)
    print(" "*20+"CLOUD GUARD")
    print("="*60)
    print("\n1. Scan Everything \n2. Scan IAM \n3. Scan S3 \n4. Scan EC2 \n5. Scan Security Groups \n6. VPC Scanner \n7. CloudTrail Scanner \n8. Exit")
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
            findings.extend(vpc_scanner(session))
            findings.extend(cloudtrail_scanner(session))
        show_result(findings)

    elif choice==2:
        run_global_scanner(scan_iam_users)
    elif choice==3:
        run_global_scanner(s3_scanner)

    elif choice==4:
        run_region_scanner(ec2_scanner)
    elif choice==5:
        run_region_scanner(security_group_scanner)

    elif choice==6:
        run_region_scanner(vpc_scanner)

    elif choice==7:
        run_region_scanner(cloudtrail_scanner)

    elif choice==8:
        print("Thank you for using CloudGuard!")
        break
    else:
        print("Please enter a number between 1 and 8.")
        