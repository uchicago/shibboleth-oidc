package net.shibboleth.idp.oidc.config;

import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.request.ConnectOAuth2RequestFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.util.Map;

@Service("shibbolethOAuth2RequestFactory")
@Primary
public class ShibbolethOAuth2RequestFactory extends ConnectOAuth2RequestFactory {
    private final Logger log = LoggerFactory.getLogger(ShibbolethOAuth2RequestFactory.class);

    @Autowired
    public ShibbolethOAuth2RequestFactory(final ClientDetailsEntityService clientDetailsService) {
        super(clientDetailsService);
    }

    @Override
    public AuthorizationRequest createAuthorizationRequest(final Map<String, String> inputParams) {
        final AuthorizationRequest request = super.createAuthorizationRequest(inputParams);
        if (inputParams.containsKey(OidcConstants.ACR_VALUES)) {
            try {
                log.debug("Authorization request contains {}. Decoding and storing values into the request", OidcConstants.ACR_VALUES);
                request.getExtensions().put(OidcConstants.ACR_VALUES,
                        URLDecoder.decode(inputParams.get(OidcConstants.ACR_VALUES), "UTF-8"));
            } catch (final Exception e) {
                log.warn("Unable to decode acr_values in the authorization request", e);
            }
        }
        return request;
    }
}
