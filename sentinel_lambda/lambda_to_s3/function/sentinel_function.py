import os
import gzip
import json
import base64
from datetime import datetime
import boto3
import logging


def handler(event, context):

    # name of s3 bucket
    S3_BUCKET = os.environ.get("S3_BUCKET", None)
    if S3_BUCKET is None:
        print("no S3 bucket in environment.  Exit")
        exit(1)

    # decompress and get data in json format
    try:
        logData = str(
            gzip.decompress(base64.b64decode(event["awslogs"]["data"])), "utf-8"
        )
    except Exception as error:
        logging.error("failed to retrieve message data: %s", error)
        return 500

    jsonBody = json.loads(logData)

    # print(logData)
    # print(jsonBody)

    records = ""
    region = "default"
    # append all records
    for logEvent in jsonBody["logEvents"]:
        snd = logEvent.get("message", "")
        if snd == "":
            exit(0)
        if records == "":
            records = snd
            region = json.loads(snd)["awsRegion"]
        else:
            records = f"{records},{snd}"

    data = f'{{"Records":[{records}]}}'
    s3_client = boto3.resource("s3")

    now = datetime.now()
    year = now.year
    month = now.month
    day = now.day
    time = f"{now.hour}{now.minute}{now.second}{now.microsecond}"
    tString = f"{year}{month}{day}_{time}"
    owner = jsonBody["owner"]
    s3_path = f"AWSLogs/{owner}/CloudTrail/{region}/{year}/{month}/{day}/{owner}_CloudTrail_{region}_{tString}.json.gz"

    s3_client.Bucket(S3_BUCKET).put_object(
        Key=s3_path,
        Body=gzip.compress(data.encode()),
        ContentEncoding="gzip",
        ContentType="application/json",
    )
    # s3_client.Bucket(S3_BUCKET).put_object(Key=s3_path, Body=data)
