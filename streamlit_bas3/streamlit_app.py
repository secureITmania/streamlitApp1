import streamlit as st
import boto3
import urllib3
import requests
import pandas as pd
from botocore.exceptions import NoCredentialsError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize urllib3 manager and results list
http = urllib3.PoolManager(cert_reqs='CERT_NONE')
listObj = []

def anonymousAccess(bucket_url, region):
    try:
        r = http.request('GET', bucket_url)
        if r.status == 200:
            a = {"anonymous_access": True, "region": region, "vulnerable_url": bucket_url}
            listObj.append(a)
    except urllib3.exceptions.HTTPError as e:
         pass

def mainEngine(bucketname):
    regions = [
        "s3-ap-northeast-1", "s3-ap-northeast-2", "s3-ap-northeast-3", "s3-ap-south-1",
        "s3-ap-southeast-1", "s3-ap-southeast-2", "s3-ca-central-1", "s3-cn-north-1",
        "s3-eu-central-1", "s3-eu-west-1", "s3-eu-west-2", "s3-eu-west-3", "s3-sa-east-1",
        "s3-us-east-1", "s3-us-east-2", "s3-us-west-1", "s3-us-west-2", "s3"
    ]
    for region in regions:
        s3url = f"https://{bucketname}.{region}.amazonaws.com"
        anonymousAccess(s3url, region)

def arbitraryListing(bucketname):
    s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID,
                             aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                             region_name=AWS_REGION)
    try:
        response = s3_client.list_objects_v2(Bucket=bucketname)
        if 'Contents' in response:
            objects = response['Contents']
            total_files = response['KeyCount']
            result = [obj['Key'] for obj in objects[:4]]  # List top 4 files
            tl = {
                "arbitraryListing": True,
                "result": result,
                "total_files": total_files
            }
            listObj.append(tl)
    except Exception as e:
        al = {
            "arbitraryListing": False,
            "result": str(e)
        }
        listObj.append(al)
 
def getBucketAcl(bucketname):
    s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID,
                             aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                             region_name=AWS_REGION)
    try:
        response = s3_client.get_bucket_acl(Bucket=bucketname)
        gba = {
            "getBucketAcl": True,
            "result": str(response)
        }
        listObj.append(gba)
    except Exception as e:
        gber = {
            "getBucketAcl": False,
            "result": str(e)
        }
        listObj.append(gber) 

def readableBucketPolicy(bucketname):
    s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID,
                             aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                             region_name=AWS_REGION)
    try:
        response = s3_client.get_bucket_policy(Bucket=bucketname)
        policy = response['Policy']  # Assuming response['Policy'] is a string
        rbp = {
            "readableBucketPolicy": True,
            "result": policy
        }
        listObj.append(rbp)
    except Exception as e:
        rber = {
            "readableBucketPolicy": False,
            "result": str(e)
        }
        listObj.append(rber)
        
def arbitraryFileUpload(bucketname):
    url = "https://raw.githubusercontent.com/secureITmania/streamlitApp1/master/streamlit_bas3/static/poc.png"
    r = requests.get(url, stream=True)
    s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID,
                             aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                             region_name=AWS_REGION)
    try:
        response = s3_client.upload_fileobj(r.raw, bucketname, 'poc.png')
        afu = {
            "arbitraryFileUpload": True,
            "result": "File uploaded successfully"
        }
        listObj.append(afu)
    except Exception as e:
        afe = {
            "arbitraryFileUpload": False,
            "result": str(e)
        }
        listObj.append(afe)
        
def display_results():
    if listObj:
        st.write("Security Assessment Results:")
        for result in listObj:
            df = pd.DataFrame([result])
            st.table(df)

# Streamlit UI components
st.title('Bucket Analyzer S3 (BAS3)')
st.markdown('follow me [@secureitmania](https://t.me/+tkUHnZ5EXS9lNmY1)')

bucket = st.text_input('Enter your S3 bucket name:')
region = st.text_input('Enter S3 bucket name region:')
secret = st.text_input('Enter Scan Auth Key:', help="Get your Auth key from https://t.me/+tkUHnZ5EXS9lNmY1")
# Set AWS credentials
AWS_ACCESS_KEY_ID = st.secrets["aws_access_key_id"]
AWS_SECRET_ACCESS_KEY = st.secrets["aws_secret_access_key"]
AWS_REGION = region

if st.button("Submit"):
    if secret == st.secrets["scan_auth_key"]:
        mainEngine(bucket)
        arbitraryListing(bucket)
        getBucketAcl(bucket)
        readableBucketPolicy(bucket)
        arbitraryFileUpload(bucket)
        display_results()
    else:
       st.write("You entered Auth key is Wrong:")
