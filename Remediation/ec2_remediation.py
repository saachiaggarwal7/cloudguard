import boto3

def remediate_imdsv2(session,instance_id):
    ec2_client=session.client("ec2")
    try:
        ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="required"
        )
        return True
    except Exception as e:
        print(e)
        return False

def remediate_detailed_monitoring(session,instance_id):
    ec2_client=session.client("ec2")
    try:
        ec2_client.monitor_instances(InstanceIds=[instance_id])
        return True
    except Exception as e:
        print(e)
        return False