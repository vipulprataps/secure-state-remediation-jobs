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

import oss2

logging.basicConfig(level=logging.INFO)


class AlibabaBucketRemovePublicAccess(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters received from the remediation service.
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
            logging.error("Missing parameters for 'payload.notificationInfo.ObjectId'.")
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        region = finding_info.get("Region", None)
        if region is None:
            logging.warning("no region specified - defaulting to us-east-1")
            region = "us-east-1"

        logging.info("parsed params")
        logging.info(f"  instance_id: {bucket_name}")
        logging.info(f"  region: {region}")

        return {"bucket_name": bucket_name}, region

    def remediate(self, auth, bucket_name):
        """Block public access to blob container

        :param client: Instance of the Azure NetworkManagementClient.
        :param resource_group_name: The name of the resource group to which the storage account belongs
        :param account_name: The name of the storage account. You must specify the
            security group name in the request.
        :param container_name: The name of the container having the violation
        :type resource_group_name: str.
        :type account_name: str.
        :type container_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        # container = client.blob_containers.get(
        #     resource_group_name=resource_group_name,
        #     account_name=account_name,
        #     container_name=container_name,
        # )
        #
        # container.public_access = PublicAccess.none

        # Revoke public access permissions for container
        logging.info("revoking public access for container")
        try:
            logging.info("    executing client.blob_containers.update")

            bucket = oss2.Bucket(auth, 'http://oss-ap-south-1.aliyuncs.com', bucket_name)
            bucket.put_bucket_acl(oss2.BUCKET_ACL_PRIVATE)
        except Exception as e:
            logging.error(f"{str(e)}")
            raise

        logging.info("successfully executed remediation")
        return 0

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params, region = self.parse(args[1])
        auth = oss2.Auth('LTAI4FzoyxjULRnRhax34zkU', 'kT4ZFNEkttLhN3wPDmvDr9WU5Yybe7')#boto3.client("ec2", region_name=region)
        logging.info("acquired auth object and parsed params - starting remediation")
        rc = self.remediate(client=auth, **params)
        return rc


if __name__ == "__main__":
    logging.info(f"{sys.argv[0]} called - running now")
    obj = AlibabaBucketRemovePublicAccess()
    obj.run(sys.argv)