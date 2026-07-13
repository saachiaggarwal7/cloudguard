import boto3

def remediate_multi_region(session,trail_name):
    cloudtrail_client=session.client("cloudtrail")
    try:
        trail=cloudtrail_client.get_trail(Name=trail_name)["Trail"]
        cloudtrail_client.update_trail(
        Name=trail_name,
        S3BucketName=trail["S3BucketName"],
        IsMultiRegionTrail=True
        )
        return True
    except Exception as e:
        print(e)
        return False
    
def remediate_log_file_validation(session,trail_name):
    cloudtrail_client=session.client("cloudtrail")
    try:
        trail=cloudtrail_client.get_trail(Name=trail_name)["Trail"]
        cloudtrail_client.update_trail(
        Name=trail_name,
        S3BucketName=trail["S3BucketName"],
        IsMultiRegionTrail=trail["IsMultiRegionTrail"],
        EnableLogFileValidation=True
        )
        return True
    except Exception as e:
        print(e)
        return False

