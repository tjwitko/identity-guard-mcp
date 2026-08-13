import boto3
# No explicit keys: the SDK resolves the pod's IRSA role from the projected token.
s3 = boto3.client("s3")
