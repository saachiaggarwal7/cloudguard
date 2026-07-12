import boto3

def delete_security_group(session,group_id):
    ec2_client=session.client("ec2")
    try:
        ec2_client.delete_security_group(GroupId=group_id)
        return True
    except Exception as e:
        print(e)
        return False
    