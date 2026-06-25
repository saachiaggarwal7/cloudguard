import boto3
from datetime import datetime,timezone
def scan_iam_users():
    iam_findings=[]
    iam_client=boto3.client('iam')
    iam_list=iam_client.list_users()

    
    for user in iam_list["Users"]:
        finding={}

        #check MFA
        mfa_devices=iam_client.list_mfa_devices(UserName=user["UserName"])
        if not mfa_devices["MFADevices"]:
            finding={
            "rule_id": "CG-IAM-001",
            "service":"iam",
            'username':user["UserName"],
            "severity":"HIGH",
            "finding":"MFA is disabled",
            "recommendation":"Enable MFA for this user"
            }
            iam_findings.append(finding)

       #checks if user has Administrator policy
        policies=iam_client.list_attached_user_policies(UserName=user["UserName"])
        for policy in policies["AttachedPolicies"]:
            if policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess" :
                finding={
                "rule_id": "CG-IAM-002",
                "service":"iam",
                'username':user["UserName"],
                "severity":"MEDIUM",
                "finding":"User has AdministratorAccess policy attached ",
                "recommendation":"Review whether full administrator privileges are required.\nFollow the principle of least privilege."
                }
                iam_findings.append(finding)
        

        #checks if access keys are unused for more than 90 days
        access_keys=iam_client.list_access_keys(UserName=user['UserName'])
        for meta_data in access_keys['AccessKeyMetadata']:
            access_key_id=meta_data["AccessKeyId"]
            last_used=iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used_date=last_used["AccessKeyLastUsed"].get("LastUsedDate")
            if last_used_date:
                days_unused=(datetime.now(timezone.utc)-last_used_date).days
                if(days_unused>=90):
                    finding={
                "rule_id": "CG-IAM-003",
                "service":"iam",
                'username':user["UserName"],
                "severity":"HIGH",
                "finding":"Access key not used for over 90 days",
                "recommendation":"Rotate or delete the access key"
                }
                    iam_findings.append(finding)
                



    if not iam_findings:
        print("No iam users found with vulnerability")
    return iam_findings
    