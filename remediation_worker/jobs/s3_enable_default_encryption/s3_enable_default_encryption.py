# Copyright (c) 2020 VMware Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import json
import logging
import sys

import boto3

logging.basicConfig(level=logging.INFO)


class S3EnableDefaultEncryption:
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters sent to the remediation job.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: Exception, JSONDecodeError
        """
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)
        finding_info = notification_info.get("FindingInfo", None)
        bucket_name = finding_info.get("ObjectId", None)

        if bucket_name is None:
            logging.error("Missing parameters for 'BUCKET_NAME'.")
            raise Exception("Missing parameters for 'BUCKET_NAME'.")

        logging.info("parsed params")
        logging.info(f"  bucket_name: {bucket_name}")

        return {"bucket_name": bucket_name}

    def remediate(self, client, bucket_name):
        """Enable default encryption for an S3 bucket using AES256.

        :param client: Instance of the AWS boto3 client.
        :param bucket_name: The name of the bucket for which to enable encryption.
        :type bucket_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        logging.info(
            f"making api call to client.put_bucket_encryption for bucket {bucket_name}"
        )
        client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
        logging.info(f"successfully executed remediation for bucket: {bucket_name}")
        return 0

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])
        client = boto3.client("s3")
        logging.info("acquired s3 client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info("s3_enable_default_encryption.py called - running now")
    obj = S3EnableDefaultEncryption()
    obj.run(sys.argv)
