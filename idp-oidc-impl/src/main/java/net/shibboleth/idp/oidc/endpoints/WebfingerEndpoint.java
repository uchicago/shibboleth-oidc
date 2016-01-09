package net.shibboleth.idp.oidc.endpoints;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * This is {@link WebfingerEndpoint}.
 */
@Controller("oidcWebfingerEndpoint")
@RequestMapping("/webfinger" )
public class WebfingerEndpoint extends org.mitre.discovery.web.DiscoveryEndpoint {
    public static final String URL = "/webfinger";

    @RequestMapping(
            method = RequestMethod.GET,
            params = {"resource", "rel=http://openid.net/specs/connect/1.0/issuer"},
            produces = {"application/json"}
    )
    @Override
    public String webfinger(@RequestParam("resource") final String resource, final Model model) {
        return super.webfinger(resource, model);
    }
}
