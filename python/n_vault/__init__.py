# Copyright 2016-2017 Nitor Creations Oy
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

""" Vault module for securely storing secrets in s3 with local encryption
with data keys from AWS KMS
"""
from os import environ
cov = None
if "VAULT_MEASURE_COVERAGE" in environ:
    from coverage import Coverage
    cov = Coverage(auto_data=True, source=["n_vault"], branch=False,
                   omit=["n_vault/__init__.py"])
    cov.start()

def stop_cov(signum, frame):
    if cov:
        cov.save()
        cov.stop()
    if signum:
        sys.exit(0)

from n_vault.vault import Vault
