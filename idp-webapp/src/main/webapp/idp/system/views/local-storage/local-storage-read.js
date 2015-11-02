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
