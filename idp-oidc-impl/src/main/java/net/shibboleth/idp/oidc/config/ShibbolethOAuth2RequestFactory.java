package net.shibboleth.idp.oidc.config;

import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.request.ConnectOAuth2RequestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service("shibbolethOAuth2RequestFactory")
@Primary
public class ShibbolethOAuth2RequestFactory extends ConnectOAuth2RequestFactory {
    @Autowired
    public ShibbolethOAuth2RequestFactory(final ClientDetailsEntityService clientDetailsService) {
        super(clientDetailsService);
    }

    @Override
    public AuthorizationRequest createAuthorizationRequest(final Map<String, String> inputParams) {
        final AuthorizationRequest request = super.createAuthorizationRequest(inputParams);
        if(inputParams.containsKey("acr_values")) {
            request.getExtensions().put("acr_values", inputParams.get("acr_values"));
        }
        return request;
    }
}
