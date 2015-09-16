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
function readLocalStorageAndSubmit(key, version) {
    var localStorageSupported = isLocalStorageSupported();
    document.form1["shib_idp_ls_supported"].value = localStorageSupported;
    if (localStorageSupported) {
        var success;
        try {
            // TODO trim key and version
            // TODO The key typeof check might be unnecessary.
            if (typeof key != 'string') {
                throw ("Key [" + key + "] must be a string");
            }
            if (isNaN(version)) {
                throw ("Version [" + version + "] must be a number");
            }
            var versionedValue = localStorage.getItem(key);
            if (versionedValue != null) {
                // TODO test
                var splitPoint = versionedValue.indexOf(":");
                if (splitPoint < 0) {
                    throw "Unable to determine version of item value";
                }
                // TODO test
                var localVersion = versionedValue.substring(0, splitPoint);
                if (isNaN(localVersion)) {
                    throw ("Local version [" + localVersion + "] must be a number");
                }
                document.form1["shib_idp_ls_version"].value = localVersion;
                if (Number(localVersion) > Number(version)) {
                    var value = versionedValue.substring(splitPoint + 1);
                    // TODO check something here ?
                    document.form1["shib_idp_ls_value"].value = value;
                }
            }
            success = "true";
        } catch (e) {
            success = "false";
            document.form1["shib_idp_ls_exception"].value = e;
        }
        document.form1["shib_idp_ls_success"].value = success;
    }
    document.form1.submit();
}
function isLocalStorageSupported() {
    try {
        localStorage.setItem("shib_idp_ls_test", "shib_idp_ls_test");
        localStorage.removeItem("shib_idp_ls_test");
        return true;
    } catch (e) {
        return false;
    }
}
