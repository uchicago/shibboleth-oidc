/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"use strict";
function writeLocalStorageAndSubmit(key, value, version) {
    var success;
    try {
        // TODO The key and value typeof checks might be unnecessary.
        if (typeof key != 'string') {
            throw("Key [" + key + "] must be a string");
        }
        if (typeof value != 'string') {
            throw("Value [" + value + "] must be a string");
        }
        if (isNaN(version)) {
            throw("Version [" + version + "] must be a number");
        }
        // TODO trim key and version and value ?
        var versionedValue = version + ":" + value;
        localStorage.setItem(key, versionedValue);
        success = "true";
    } catch (e) {
        success = "false";
        document.form1["shib_idp_ls_exception"].value = e;
    }
    document.form1["shib_idp_ls_success"].value = success;
    document.form1.submit();
}