import boto3

def ec2_scanner(session):
    region=session.region_name or "Global"
    ec2_findings=[]
    ec2_client=session.client("ec2")
    response=ec2_client.describe_instances()
    for reservation in response['Reservations']:
        for instance in reservation["Instances"]:
            instance_name=instance['InstanceId']
            state=instance["State"]["Name"]
            if state!='running':
                continue
            for tag in instance.get('Tags',[]):
                if tag['Key']=='Name':
                    instance_name=tag['Value']

            #to find public instances
            if instance.get('PublicIpAddress'):
                finding={
                            "rule_id": "CG-EC2-001",
                            "service": "EC2",
                            'region':region,
                            "resource": instance_name,
                            "severity": "HIGH",
                            "finding": f"Instance has a public IP address ({instance.get('PublicIpAddress')}).",
                            "recommendation": "Remove the public IP or place the instance in a private subnet unless Internet access is required."
                        }
                ec2_findings.append(finding)
            
            #checking if IMDSv2 is enforced or not
            metadata=instance['MetadataOptions']
            imds=metadata['HttpTokens']
            if imds=='optional':
                finding={
                            "rule_id": "CG-EC2-002",
                            "service": "EC2",
                            'region':region,
                            "resource": instance_name,
                            "severity": "HIGH",
                            "finding": "IMDSv2 is not enforced. Instance allows IMDSv1 requests.",
                            "recommendation":"Require IMDSv2 by setting HttpTokens to 'required'."
                        }
                ec2_findings.append(finding)

            #checking whether detailed monitoring is enabled or disabled
            monitoring=instance['Monitoring']
            if monitoring['State']=='disabled':
                finding={
                            "rule_id": "CG-EC2-003",
                            "service": "EC2",
                            'region':region,
                            "resource": instance_name,
                            "severity": "LOW",
                            "finding": "Detailed CloudWatch monitoring is disabled.",
                            "recommendation":"Enable detailed monitoring for better visibility and faster detection of operational or security issues."
                        }
                ec2_findings.append(finding)

            #check if EBS volume is encrypted or not
            block_devices=instance['BlockDeviceMappings']
            unencrypted_volume=False
            for block_device in block_devices:
                volume=block_device.get("Ebs")
                if not volume:
                    continue
                volume_id=volume['VolumeId']
                volumes=ec2_client.describe_volumes(VolumeIds=[volume_id])['Volumes']
                for volume_block in volumes:
                    if not volume_block["Encrypted"]:
                        finding={
                            "rule_id": "CG-EC2-004",
                            "service": "EC2",
                            'region':region,
                            "resource": instance_name,
                            "severity": "HIGH",
                            "finding": "EBS volume is not encrypted",
                            "recommendation":"Create an encrypted copy of the volume or use encrypted EBS volumes for sensitive data."
                        }
                        ec2_findings.append(finding)
                        unencrypted_volume=True
                        break
                if unencrypted_volume:
                    break
                        
                
    if not ec2_findings:
        print("No ec2 instances found with vulnerability")
    return ec2_findings
    