package net.shibboleth.idp.oidc.endpoints;

import net.shibboleth.idp.oidc.util.OidcUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * The discovery endpoint.
 */
@Controller("oidcWellknownEndpoint")
@RequestMapping("/oidc/" + org.mitre.discovery.web.DiscoveryEndpoint.WELL_KNOWN_URL)
public final class WellKnownEndpoint extends org.mitre.discovery.web.DiscoveryEndpoint {
    /** URL endpoint. */
    public static final String URL = "/oidc/" + WELL_KNOWN_URL;

    @RequestMapping(method= RequestMethod.GET)
    public String defaultEndpoint(final Model model) {
        final String view = super.providerConfiguration(model);
        model.mergeAttributes(OidcUtils.buildOidcServerConfigurationModelForDiscovery(model));
        return view;
    }
}


