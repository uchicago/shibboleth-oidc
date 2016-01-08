package net.shibboleth.idp.oidc.endpoints;

import com.nimbusds.jose.jwk.JWK;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.openid.connect.view.JWKSetView;
import org.mitre.openid.connect.web.JWKSetPublishingEndpoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

/**
 * A JWK endpoint that remaps the controller.
 */
@Controller("jwkPublishingEndpoint")
public class JWKPublishingEndpoint extends JWKSetPublishingEndpoint {

    /** URL endpoint for JWK used to map requests. */
    public static final String URL = "/oidc/jwk";

    @Autowired
    private JWTSigningAndValidationService jwtService;

    @RequestMapping(value = URL, produces = MediaType.APPLICATION_JSON_VALUE)
    @Override
    public String getJwk(final Model m) {
        final Map<String, JWK> keys = jwtService.getAllPublicKeys();
        m.addAttribute("keys", keys);
        return JWKSetView.VIEWNAME;
    }


}
