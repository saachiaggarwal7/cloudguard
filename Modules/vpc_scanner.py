import boto3

def vpc_scanner(session):
    findings=[]
    region=session.region_name
    ec2_client=session.client('ec2')
    response=ec2_client.describe_vpcs()
    vpcs=response['Vpcs']
    for vpc in vpcs:
        resource=vpc["VpcId"]
        for tag in vpc.get('Tags',[]):
            if tag['Key']=='Name':
                resource=f"{tag['Value']} ({vpc['VpcId']})"
                break
        
        #to check if there are default Vpcs
        if vpc.get('IsDefault'):
            finding={
                "rule_id": "CG-VPC-001",
                "service":"VPC",
                'region':region,
                'resource':resource,
                "severity":"LOW",
                "finding":"Default VPC exists.",
                "recommendation":"Delete the default VPC if it is not required."
            }
            findings.append(finding)
        #Flow Logs checks
        flow_logs=ec2_client.describe_flow_logs(Filters=[{"Name":"resource-id","Values":[vpc["VpcId"]]}])
        if not flow_logs['FlowLogs']:
            finding={
                "rule_id": "CG-VPC-002",
                "service":"VPC",
                'region':region,
                'resource':resource,
                "severity":"MEDIUM",
                "finding":"VPC Flow Logs are disabled.",
                "recommendation":"Enable VPC Flow Logs and send them to CloudWatch Logs or Amazon S3 for monitoring and incident investigation."
            }
            findings.append(finding)

        #checks if dns hostnames is disabled
        dns_hostnames=ec2_client.describe_vpc_attribute(VpcId=vpc["VpcId"],Attribute="enableDnsHostnames")['EnableDnsHostnames']
        if not dns_hostnames['Value']:
            finding = {
                "rule_id": "CG-VPC-003",
                "service": "VPC",
                "region": region,
                "resource": resource,
                "severity": "MEDIUM",
                "finding": "VPC DNS Hostnames are disabled.",
                "recommendation": "Enable DNS Hostnames unless there is a specific reason to disable them."
                }
            findings.append(finding)

        #checks if dns resolution is disabled
        dns_support=ec2_client.describe_vpc_attribute(VpcId=vpc["VpcId"],Attribute="enableDnsSupport")['EnableDnsSupport']
        if not dns_support['Value']:
            finding = {
                "rule_id": "CG-VPC-004",
                "service": "VPC",
                "region": region,
                "resource": resource,
                "severity": "HIGH",
                "finding": "VPC DNS Resolution is disabled.",
                "recommendation": "Enable DNS Resolution unless there is a specific reason to disable it."
                }
            findings.append(finding)
    
    if not findings:
        print("no vulnerability found")
    return findings