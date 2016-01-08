package net.shibboleth.idp.oidc.client;

import net.shibboleth.idp.oidc.jwk.IntrospectionEndpoint;
import net.shibboleth.idp.oidc.jwk.JWKPublishingEndpoint;
import net.shibboleth.idp.oidc.jwk.RevocationEndpoint;
import net.shibboleth.idp.oidc.jwk.TokenEndpoint;
import net.shibboleth.idp.oidc.login.AuthorizeEndpoint;
import net.shibboleth.idp.oidc.userinfo.UserInfoEndpoint;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.HashMap;
import java.util.Map;

/**
 * The discovery endpoint.
 */
@Controller("oidcDiscoveryEndpoint")
@RequestMapping("/oidc/" + org.mitre.discovery.web.DiscoveryEndpoint.OPENID_CONFIGURATION_URL)
public final class DiscoveryEndpoint extends org.mitre.discovery.web.DiscoveryEndpoint {
    /** URL endpoint. */
    public static final String URL = "/oidc/" + OPENID_CONFIGURATION_URL;

    @RequestMapping(method= RequestMethod.GET)
    @Override
    public String providerConfiguration(final Model model) {
        final String view = super.providerConfiguration(model);

        final Map<String, Object> m = Map.class.cast(model.asMap().get("entity"));

        final String baseUrl = m.get("issuer").toString();
        m.put("authorization_endpoint", baseUrl + "profile" + AuthorizeEndpoint.URL);
        m.put("token_endpoint", baseUrl + "profile" + TokenEndpoint.URL);
        m.put("userinfo_endpoint", baseUrl + "profile" + UserInfoEndpoint.URL);
        m.put("jwks_uri", baseUrl + "profile" + JWKPublishingEndpoint.URL);
        m.put("revocation_endpoint", baseUrl + "profile" + RevocationEndpoint.URL);
        m.put("introspection_endpoint", baseUrl + "profile" + IntrospectionEndpoint.URL);
        
        m.remove("service_documentation");
        m.remove("op_policy_uri");
        m.remove("op_tos_uri");

        model.mergeAttributes(m);

        return view;
    }
}


