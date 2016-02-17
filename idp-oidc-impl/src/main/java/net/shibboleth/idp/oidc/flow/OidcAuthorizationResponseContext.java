package net.shibboleth.idp.oidc.flow;


import org.opensaml.messaging.context.BaseContext;

public class OidcAuthorizationResponseContext extends BaseContext {

    private OidcResponse oidcResponse;

    public OidcResponse getOidcResponse() {
        return oidcResponse;
    }

    public void setOidcResponse(final OidcResponse oidcResponse) {
        this.oidcResponse = oidcResponse;
    }

}
