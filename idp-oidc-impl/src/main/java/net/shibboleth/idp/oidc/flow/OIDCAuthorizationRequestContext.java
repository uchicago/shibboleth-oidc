package net.shibboleth.idp.oidc.flow;


import com.google.common.base.MoreObjects;
import org.mitre.openid.connect.request.ConnectRequestParameters;
import org.opensaml.messaging.context.BaseContext;
import org.springframework.security.oauth2.provider.AuthorizationRequest;

import javax.annotation.Nonnull;

public class OIDCAuthorizationRequestContext extends BaseContext {

    private boolean forceAuthentication;

    @Nonnull
    private AuthorizationRequest authorizationRequest;

    public AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    public void setAuthorizationRequest(final AuthorizationRequest authorizationRequest) {
        this.authorizationRequest = authorizationRequest;
    }

    public String getClientId() {
        return this.authorizationRequest.getClientId();
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

    public Object getLoginHint() {
        return authorizationRequest.getExtensions().get(ConnectRequestParameters.LOGIN_HINT);
    }

    public String getMaxAge() {
        return (String) authorizationRequest.getExtensions().get(ConnectRequestParameters.MAX_AGE);
    }

    public String getRedirectUri() {
        return this.authorizationRequest.getRedirectUri();
    }

    public String getState() {
        return this.authorizationRequest.getState();
    }

    public boolean isForceAuthentication() {
        return forceAuthentication;
    }

    public void setForceAuthentication(final boolean forceAuthentication) {
        this.forceAuthentication = forceAuthentication;
    }
}
