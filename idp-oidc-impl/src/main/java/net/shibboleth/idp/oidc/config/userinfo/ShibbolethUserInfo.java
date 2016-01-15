package net.shibboleth.idp.oidc.config.userinfo;

import com.google.gson.JsonObject;
import org.mitre.openid.connect.model.DefaultUserInfo;

public class ShibbolethUserInfo extends DefaultUserInfo {

    @Override
    public JsonObject toJson() {
        final JsonObject json = super.toJson();
        json.remove("zone_info");
        json.addProperty("zoneinfo", getZoneinfo());
        return json;
    }
}
