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