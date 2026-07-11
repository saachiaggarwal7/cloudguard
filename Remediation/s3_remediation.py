import boto3

def remediate_block_public_access(session,bucket_name):
    s3_client=session.client("s3")

    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls":True,
                "IgnorePublicAcls":True,
                "BlockPublicPolicy":True,
                "RestrictPublicBuckets":True
            }
        )
        return True
    except Exception as e:
        print(e)
        return False


def remediate_versioning(session,bucket_name):
    s3_client=session.client("s3")
    try:
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={
                "Status":"Enabled"
            }
        )
        return True
    except Exception as e:
        print(e)
        return False
