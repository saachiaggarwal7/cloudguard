import boto3

def remediate_flow_logs(session,vpc_id):
    ec2_client=session.client("ec2")
    log_group=input("Enter CloudWatch Log Group Name: ").strip()
    role_arn = input("Enter IAM Role ARN: ").strip()
    try:
        response=ec2_client.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName=log_group,
            DeliverLogsPermissionArn=role_arn
        )
        if response["Unsuccessful"]:
            print(response["Unsuccessful"])
            return False
        return True
    except Exception as e:
        print(e)
        return False
        