import boto3
from datetime import datetime,timezone
def scan_iam_users(session):
    iam_findings=[]
    iam_client=session.client('iam')
    iam_list=iam_client.list_users()

    #to check whether root has MFA enabled or not
    root_detail=iam_client.get_account_summary()['SummaryMap']
    if root_detail['AccountMFAEnabled']==0:
        finding={
            "rule_id": "CG-IAM-001",
            "service":"IAM",
            'region':"Global",
            'resource':"AWS ROOT Account",
            "severity":"CRITICAL",
            "finding":"MFA is disabled in root account",
            "recommendation":"Enable MFA for root account"
            }
        iam_findings.append(finding)
        
    for user in iam_list["Users"]:
       
        #check MFA 
        mfa_devices=iam_client.list_mfa_devices(UserName=user["UserName"])
        if not mfa_devices["MFADevices"]:
            finding={
            "rule_id": "CG-IAM-002",
            "service":"IAM",
            'region':"Global",
            'resource':user["UserName"],
            "severity":"HIGH",
            "finding":"MFA is disabled",
            "recommendation":"Enable MFA for this user"
            }
            iam_findings.append(finding)

       #checks if user has Administrator policy

       # 1. Check directly attached Managed Policy
        attached_user_policies=iam_client.list_attached_user_policies(UserName=user["UserName"])
        for policy in attached_user_policies["AttachedPolicies"]:
            if policy["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess" :
                finding={
                "rule_id": "CG-IAM-003",
                "service":"IAM",
                'region':"Global",
                'resource':user["UserName"],
                "severity":"MEDIUM",
                "finding":f"AdministratorAccess policy is directly attached to the user- {user['UserName']}",
                "recommendation":"Review whether full administrator privileges are required. Follow the principle of least privilege."
                }
                iam_findings.append(finding)
        
        # 2. Check directly attached Inline Policy
        inline_user_policies=iam_client.list_user_policies(UserName=user['UserName'])['PolicyNames']
        if inline_user_policies:
                finding={
                "rule_id": "CG-IAM-005",
                "service":"IAM",
                'region':"Global",
                'resource':user["UserName"],
                "severity":"LOW",
                "finding":f"One or more Inline IAM policies are attached to the user- {user['UserName']} ",
                "recommendation":"Review inline IAM policies for excessive permissions and follow the principle of least privilege."
                }
                iam_findings.append(finding)

        # 3. Check policies inherited from the user's Groups
        user_groups=iam_client.list_groups_for_user(UserName=user['UserName'])['Groups']
        for group in user_groups:
            group_name=group['GroupName']

            # 3a. Check group's attached Managed Policies
            attached_group_policy=iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
            for policy in attached_group_policy:
                if policy['PolicyName'] =="AdministratorAccess":
                    finding={
                            "rule_id": "CG-IAM-004",
                            "service":"IAM",
                            'region':"Global",
                            'resource':user["UserName"],
                            "severity":"MEDIUM",
                            "finding":f"AdministratorAccess policy is inherited via {group_name} ",
                            "recommendation":"Review whether full administrator privileges are required. Follow the principle of least privilege."
                        }
                    iam_findings.append(finding)
             
            #3b. Check group's attached Inline Policies
            inline_group_policies=iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
            if inline_group_policies:
                finding={
                            "rule_id": "CG-IAM-006",
                            "service":"IAM",
                            'region':"Global",
                            'resource':user["UserName"],
                            "severity":"LOW",
                            "finding":f"Inline policy is inherited via {group_name}",
                            "recommendation":"Review inline IAM policies for excessive permissions and follow the principle of least privilege."
                }
                iam_findings.append(finding)

        access_keys=iam_client.list_access_keys(UserName=user['UserName'])
        for meta_data in access_keys['AccessKeyMetadata']:
            access_key_id=meta_data["AccessKeyId"]
            last_used=iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used_date=last_used["AccessKeyLastUsed"].get("LastUsedDate")
            #checks if access keys are unused for more than 90 days
            if last_used_date:
                days_unused=(datetime.now(timezone.utc)-last_used_date).days
                if(days_unused>=90):
                    finding={
                "rule_id": "CG-IAM-007",
                "service":"IAM",
                'region':"Global",
                'resource':user["UserName"],
                "access_key": access_key_id,
                "severity":"HIGH",
                "finding":f"Access key- {access_key_id} not used for over 90 days",
                "recommendation":"Rotate or delete unused access keys according to your organization's key rotation policy."
                }
                    iam_findings.append(finding)

            #checks if access key has ever been used
            if last_used_date is None:
                finding = {
                        "rule_id": "CG-IAM-008",
                        "service": "IAM",
                        'region':"Global",
                        "resource": user["UserName"],
                        "access_key": access_key_id,
                        "severity": "LOW",
                        "finding": f"Access key {access_key_id} has never been used.",
                        "recommendation": "Delete unused access keys if they are no longer required."
                        }
                iam_findings.append(finding)
                
            #checks if key is older than or equal to 180 days
            create_date=meta_data['CreateDate']
            date=(datetime.now(timezone.utc)-create_date).days
            if date>=180:
                finding = {
                        "rule_id": "CG-IAM-009",
                        "service": "IAM",
                        'region':"Global",
                        "resource": user["UserName"],
                        "access_key": access_key_id,
                        "severity": "HIGH",
                        "finding": f"Access key {access_key_id} is older than or equal to 180 days.",
                        "recommendation": "Rotate the access key."
                        }
                iam_findings.append(finding)
                

    if not iam_findings:
        print("No iam users found with vulnerability")
    return iam_findings
    