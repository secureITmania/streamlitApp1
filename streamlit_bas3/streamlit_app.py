import streamlit as st
import boto3
import urllib3
import requests
import base64
from io import BytesIO
import pandas as pd
from botocore.exceptions import NoCredentialsError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize urllib3 manager and results list
http = urllib3.PoolManager(cert_reqs='CERT_NONE')
listObj = []


# Function to download file from S3
def download_s3_file(s3_uri, region):
    # Split the S3 URI into bucket name and key
    if not s3_uri.startswith("s3://"):
        s3_uri = "s3://" + s3_uri
    parts = s3_uri.replace("s3://", "").split("/", 1)
    if len(parts) != 2:
        st.error("Invalid S3 URI format. Please use 'bucketname/key'.")
        return None

    bucket_name, key = parts

    # Create an S3 client
    s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID,
                             aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                             region_name=AWS_REGION)

    try:
        # Download the file content
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        file_content = response['Body'].read()
        return BytesIO(file_content)
    except NoCredentialsError:
        st.error("Credentials not available.")
        return None
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
        return None
        
def getRegion(bucket_url, region):
    http = urllib3.PoolManager(cert_reqs='CERT_NONE')
    listObj = []

    try:
        r = http.request('GET', bucket_url)
        response_body = r.data.decode('utf-8')
        if r.status == 403:
            if '<Code>AccessDenied</Code>' in response_body:
                st.write(f"Region: {region}, Bucket URL: {bucket_url}")

    except urllib3.exceptions.HTTPError as e:
        st.error(f"HTTPError: {str(e)}")
        
def bucketRegionFuzz(bucketname):
    regions = [
    'us-east-1',          # US East (N. Virginia)
    'us-east-2',          # US East (Ohio)
    'us-west-1',          # US West (N. California)
    'us-west-2',          # US West (Oregon)
    'af-south-1',         # Africa (Cape Town)
    'ap-east-1',          # Asia Pacific (Hong Kong)
    'ap-south-1',         # Asia Pacific (Mumbai)
    'ap-south-2',         # Asia Pacific (Hyderabad)
    'ap-southeast-1',     # Asia Pacific (Singapore)
    'ap-southeast-2',     # Asia Pacific (Sydney)
    'ap-southeast-3',     # Asia Pacific (Jakarta)
    'ap-southeast-4',     # Asia Pacific (Melbourne)
    'ap-northeast-1',     # Asia Pacific (Tokyo)
    'ap-northeast-2',     # Asia Pacific (Seoul)
    'ap-northeast-3',     # Asia Pacific (Osaka)
    'ca-central-1',       # Canada (Central)
    'eu-central-1',       # Europe (Frankfurt)
    'eu-central-2',       # Europe (Zurich)
    'eu-west-1',          # Europe (Ireland)
    'eu-west-2',          # Europe (London)
    'eu-west-3',          # Europe (Paris)
    'eu-south-1',         # Europe (Milan)
    'eu-south-2',         # Europe (Spain)
    'eu-north-1',         # Europe (Stockholm)
    'me-central-1',       # Middle East (UAE)
    'me-south-1',         # Middle East (Bahrain)
    'sa-east-1'           # South America (São Paulo)
]
    for region in regions:
        s3url = f"https://{bucketname}.s3.{region}.amazonaws.com"
        getRegion(s3url, region)
        
def anonymousAccess(bucket_url, region):
    try:
        r = http.request('GET', bucket_url)
        if r.status == 200:
            a = {"anonymous_access": True, "region": region, "vulnerable_url": bucket_url}
            listObj.append(a)
    except urllib3.exceptions.HTTPError as e:
         pass

def bucketIndexing(bucketname):
    regions = [
    'us-east-1',          # US East (N. Virginia)
    'us-east-2',          # US East (Ohio)
    'us-west-1',          # US West (N. California)
    'us-west-2',          # US West (Oregon)
    'af-south-1',         # Africa (Cape Town)
    'ap-east-1',          # Asia Pacific (Hong Kong)
    'ap-south-1',         # Asia Pacific (Mumbai)
    'ap-south-2',         # Asia Pacific (Hyderabad)
    'ap-southeast-1',     # Asia Pacific (Singapore)
    'ap-southeast-2',     # Asia Pacific (Sydney)
    'ap-southeast-3',     # Asia Pacific (Jakarta)
    'ap-southeast-4',     # Asia Pacific (Melbourne)
    'ap-northeast-1',     # Asia Pacific (Tokyo)
    'ap-northeast-2',     # Asia Pacific (Seoul)
    'ap-northeast-3',     # Asia Pacific (Osaka)
    'ca-central-1',       # Canada (Central)
    'eu-central-1',       # Europe (Frankfurt)
    'eu-central-2',       # Europe (Zurich)
    'eu-west-1',          # Europe (Ireland)
    'eu-west-2',          # Europe (London)
    'eu-west-3',          # Europe (Paris)
    'eu-south-1',         # Europe (Milan)
    'eu-south-2',         # Europe (Spain)
    'eu-north-1',         # Europe (Stockholm)
    'me-central-1',       # Middle East (UAE)
    'me-south-1',         # Middle East (Bahrain)
    'sa-east-1'           # South America (São Paulo)
]
    for region in regions:
        s3url = f"https://{bucketname}.s3.{region}.amazonaws.com"
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

#define scan type
scan_types = ["bucket-scan", "s3-file-download", "domain-based-s3-region-scan"]
scan_type = st.selectbox("Select the Scan Type", scan_types)

# Set AWS credentials
AWS_ACCESS_KEY_ID = st.secrets["aws_access_key_id"]
AWS_SECRET_ACCESS_KEY = st.secrets["aws_secret_access_key"]

if scan_type == "bucket-scan":
    bucket = st.text_input('Enter your S3 bucket name:')
    region = st.text_input('Enter S3 bucket name region:')
    secret = st.text_input('Enter Scan Auth Key:', help="Get your Auth key from https://t.me/+tkUHnZ5EXS9lNmY1")
    AWS_REGION = region
    if st.button("Submit"):
        if secret == st.secrets["scan_auth_key"]:
            bucketIndexing(bucket)
            arbitraryListing(bucket)
            getBucketAcl(bucket)
            readableBucketPolicy(bucket)
            arbitraryFileUpload(bucket)
            display_results()
        else:
           st.write("You entered Auth key is Wrong:")
elif scan_type == "s3-file-download":
    fileuri = st.text_input('Enter S3 file URI', help="example: bucket-name/path/to/file.png")
    region = st.text_input('Enter S3 bucket name region:')
    secret = st.text_input('Enter Scan Auth Key:', help="Get your Auth key from https://t.me/+tkUHnZ5EXS9lNmY1")
    AWS_REGION = region
    if st.button("Submit"):
        if secret == st.secrets["scan_auth_key"]:
            file = download_s3_file(fileuri, AWS_REGION)
            if file:
                # Determine the file extension
                file_extension = fileuri.split('.')[-1]
                file_name = f"downloaded_file.{file_extension}"
                
                # Encode file to base64
                b64 = base64.b64encode(file.getvalue()).decode()
                href = f'<a href="data:file/{file_extension};base64,{b64}" download="{file_name}">Download {file_name}</a>'
                
                # Provide download hyperlink
                st.markdown(href, unsafe_allow_html=True)
        else:
           st.write("You entered Auth key is Wrong:")
elif scan_type == "domain-based-s3-region-scan":
    bucket_domain = st.text_input('Enter S3 bucket domain name', help="example: bucketname.example.com")
    secret = st.text_input('Enter Scan Auth Key:', help="Get your Auth key from https://t.me/+tkUHnZ5EXS9lNmY1")
    if st.button("Submit"):
        if secret == st.secrets["scan_auth_key"]:
            bucketRegionFuzz(bucket_domain)
        
