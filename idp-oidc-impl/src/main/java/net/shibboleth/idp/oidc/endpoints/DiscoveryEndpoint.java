package net.shibboleth.idp.oidc.endpoints;

import net.shibboleth.idp.oidc.util.OIDCUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * The discovery endpoint.
 */
@Controller("oidcDiscoveryEndpoint")
@RequestMapping("/openid-configuration")
public final class DiscoveryEndpoint extends org.mitre.discovery.web.DiscoveryEndpoint {
    /** URL endpoint. */
    public static final String URL = "/openid-configuration";

    @RequestMapping(method= RequestMethod.GET)
    @Override
    public String providerConfiguration(final Model model) {
        final String view = super.providerConfiguration(model);
        model.mergeAttributes(OIDCUtils.buildOidcServerConfigurationModelForDiscovery(model));
        return view;
    }
}


