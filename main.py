from files.iam_auditor import scan_iam_users
from files.ec2_scanner import ec2_scanner
from files.s3_scanner import s3_scanner
from files.security_group_scanner import security_group_scanner
from files.report_generator import generate_report


findings=[]

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
    print("\n1. Scan Everything \n2. Scan IAM \n3. Scan S3 \n4. Scan EC2 \n5. Scan Security Groups \n6. Generate Report \n7. Exit")
    try:
        choice=int(input("Enter choice:"))
    except ValueError:
        print("Please enter a valid number.")
        continue
    if choice==1:
        findings=[]
        findings.extend(scan_iam_users())
        findings.extend(s3_scanner())
        findings.extend(ec2_scanner())
        findings.extend(security_group_scanner())
        display_finding(findings)
    elif choice==2:
        findings=[]
        findings.extend(scan_iam_users())
        display_finding(findings)
    elif choice==3:
        findings=[]
        findings.extend(s3_scanner())
        display_finding(findings)
    elif choice==4:
        findings=[]
        findings.extend(ec2_scanner())
        display_finding(findings)
    elif choice==5:
        findings=[]
        findings.extend(security_group_scanner())
        display_finding(findings)
    elif choice==6:
        if findings:
            generate_report(findings)
            print("Report generated successfully!")
        else:
            print("No scan results available. Please run a scan first.")
    elif choice==7:
        print("Thank you for using CloudGuard!")
        break
    else:
        print("Please enter a number between 1 and 7.")





