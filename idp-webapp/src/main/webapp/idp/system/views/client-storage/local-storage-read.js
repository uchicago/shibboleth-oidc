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
function readLocalStorage(key) {
    var success;
    try {
        var value = localStorage.getItem(key);
        if (value != null) {
            document.form1["shib_idp_ls_value." + key].value = value;
        }
        success = "true";
    } catch (e) {
        success = "false";
        document.form1["shib_idp_ls_exception." + key].value = e;
    }
    document.form1["shib_idp_ls_success." + key].value = success;
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
