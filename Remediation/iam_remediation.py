import boto3

def delete_access_key(session,user_name,access_key):
    iam_client=session.client("iam")
    try:
        iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key)
        return True
    except Exception as e:
        print(e)
        return False
    
