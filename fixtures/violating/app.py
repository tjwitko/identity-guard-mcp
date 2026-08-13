# Deliberately non-compliant: this is the fixture that proves the rules fire.
import os
import boto3
import psycopg2
import requests

s3 = boto3.client("s3", aws_access_key_id="AKIA...", aws_secret_access_key="...")
conn = psycopg2.connect(host="db", user="app", password=os.environ["DB_PASS"])
requests.get("https://api.internal/x", auth=("svc", "s3cret"))
