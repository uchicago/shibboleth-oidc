package net.shibboleth.idp.oidc.flow;


import com.google.common.base.MoreObjects;
import org.opensaml.messaging.context.BaseContext;
import org.springframework.security.oauth2.provider.AuthorizationRequest;

import javax.annotation.Nonnull;

public class OidcAuthorizationRequestContext extends BaseContext {

    @Nonnull
    private AuthorizationRequest authorizationRequest;

    public AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    public void setAuthorizationRequest(final AuthorizationRequest authorizationRequest) {
        this.authorizationRequest = authorizationRequest;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("authorizationRequestClientId", authorizationRequest.getClientId())
                .add("authorizationRequestRedirectUri", authorizationRequest.getRedirectUri())
                .add("authorizationRequestRequestParameters", authorizationRequest.getRequestParameters())
                .add("authorizationRequestExtensions", authorizationRequest.getExtensions().values())
                .add("authorizationRequestScope", authorizationRequest.getScope())
                .add("authorizationRequestState", authorizationRequest.getState())
                .add("authorizationRequestResponseTypes", authorizationRequest.getResponseTypes())
                .toString();
    }
}
