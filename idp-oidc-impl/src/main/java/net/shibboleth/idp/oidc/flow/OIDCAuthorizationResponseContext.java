package net.shibboleth.idp.oidc.flow;


import org.opensaml.messaging.context.BaseContext;

public class OIDCAuthorizationResponseContext extends BaseContext {

    private OIDCResponse oidcResponse;

    public OIDCResponse getOidcResponse() {
        return oidcResponse;
    }

    public void setOidcResponse(final OIDCResponse oidcResponse) {
        this.oidcResponse = oidcResponse;
    }

}
