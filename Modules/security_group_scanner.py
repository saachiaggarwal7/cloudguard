import boto3

def security_group_scanner(session):
    sg_findings=[]
    region=session.region_name or "Global"
    ec2_client=session.client('ec2')
    response=ec2_client.describe_security_groups()
    security_groups=response.get('SecurityGroups')
    for security_group in security_groups:
        ip_permissions=security_group.get('IpPermissions',[])
        group_name=security_group['GroupName']
        group_id=security_group['GroupId']

        for ip_permission in ip_permissions:

            # SSH(22) Open to the network
            if "FromPort" in ip_permission:
                if ip_permission['FromPort']==22:
                    for ip_range in ip_permission.get('IpRanges',[]):
                        if ip_range['CidrIp']=='0.0.0.0/0':
                            finding={
                                    "rule_id": "CG-SG-001",
                                    "service": "Security Group",
                                    'region':region,
                                    "resource": f"{group_name} ({group_id})",
                                    "severity": "HIGH",
                                    "finding": "SSH (22) is open to the Internet.",
                                    "recommendation": "Restrict SSH access to trusted IP addresses instead of 0.0.0.0/0."
                                    }
                            sg_findings.append(finding)
                            break
                # RDP(3389) Open to the network
                elif ip_permission['FromPort']==3389:
                    for ip_range in ip_permission.get('IpRanges',[]):
                        if ip_range['CidrIp']=='0.0.0.0/0':
                            finding={
                                    "rule_id": "CG-SG-002",
                                    "service": "Security Group",
                                    'region':region,
                                    "resource": f"{group_name} ({group_id})",
                                    "severity": "HIGH",
                                    "finding": "RDP (3389) is open to the Internet.",
                                    "recommendation": "Restrict RDP access to trusted IP addresses instead of 0.0.0.0/0."
                                    }
                            sg_findings.append(finding)
                            break
            
            #All Traffic
            if ip_permission.get('IpProtocol')=='-1':
                for ip_range in ip_permission.get('IpRanges',[]):
                        if ip_range['CidrIp']=='0.0.0.0/0':
                            finding={
                                "rule_id": "CG-SG-003",
                                "service": "Security Group",
                                'region':region,
                                "resource": f"{group_name} ({group_id})",
                                "severity": "CRITICAL",
                                "finding": "All inbound traffic is allowed from the Internet.",
                                "recommendation": "Restrict inbound access by allowing only required ports and trusted IP ranges."
                            }
                            sg_findings.append(finding)
                            break
    
    #unused SG
    interfaces=ec2_client.describe_network_interfaces()['NetworkInterfaces']
    used_groups=set()
    for interface in interfaces:
        for group in interface["Groups"]:
            used_groups.add(group['GroupId'])
    for security_group in security_groups:
        group_id=security_group['GroupId']
        group_name=security_group["GroupName"]
        if group_name=="default":
            continue
        if group_id not in used_groups:
            finding={
                        "rule_id": "CG-SG-004",
                        "service": "Security Group",
                        'region':region,
                        "resource": f"{group_name} ({group_id})",
                        "severity": "LOW",
                        "finding": "Security Group is not attached to any network interface.",
                        "recommendation": "Delete unused security groups or attach them only if they are required."
                    }
            sg_findings.append(finding)


    if not sg_findings:
        print("no vulnerability found")
    return sg_findings