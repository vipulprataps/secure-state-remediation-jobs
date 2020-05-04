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

import pytest

from remediation_worker.jobs.rds_backup_retention_30_days.rds_backup_retention_30_days import (
    RDSBackupRetention30Days,
)


@pytest.fixture
def valid_payload1():
    return """
{
    "notificationInfo": {
        "FindingInfo": {
            "ObjectId": "db_instance_id",
            "Region": "region"
        }
    }
}
"""


class TestRDSBackupRetention30Days(object):
    def test_parse_payload(self, valid_payload1):
        params = RDSBackupRetention30Days().parse(valid_payload1)
        assert params["db_instance_id"] == "db_instance_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        class TestClient(object):
            def describe_db_instances(self, **kwargs):
                return {"DBInstances": [{"BackupRetentionPeriod": 29}]}

            def modify_db_instance(self, **kwargs):
                return None

        client = TestClient()
        action = RDSBackupRetention30Days()
        assert action.remediate(client, "db_instance_id") == 0

    def test_remediate_with_exception(self):
        class TestClient(object):
            def describe_db_instances(self, **kwargs):
                return {"DBInstances": [{"BackupRetentionPeriod": 29}]}

            def modify_db_instance(self, **kwargs):
                raise RuntimeError("Exception")

        client = TestClient()
        action = RDSBackupRetention30Days()
        with pytest.raises(Exception):
            assert action.remediate(client, "db_instance_id")
