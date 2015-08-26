package net.shibboleth.idp.oidc.flow;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.SystemScope;
import org.springframework.security.oauth2.provider.AuthorizationRequest;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 *
 */
public class OpenIdConnectResponse {

    private String redirectUri;

    private AuthorizationRequest authorizationRequest;

    private ClientDetailsEntity client;

    private Set<SystemScope> scopes = new LinkedHashSet<>();

    private Map<String, Map<String, String>> claims = new LinkedHashMap<>();

    private int count;

    private Set<String> contacts = new HashSet<>();

    private Map<String, String> authorizationRequestParameters;

    private boolean gras;

    public AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    public void setAuthorizationRequest(final AuthorizationRequest authorizationRequest) {
        this.authorizationRequest = authorizationRequest;
    }

    public ClientDetailsEntity getClient() {
        return client;
    }

    public void setClient(final ClientDetailsEntity client) {
        this.client = client;
    }

    public Set<SystemScope> getScopes() {
        return scopes;
    }

    public void setScopes(final Set<SystemScope> scopes) {
        this.scopes = scopes;
    }

    public Map<String, Map<String, String>> getClaims() {
        return claims;
    }

    public void setClaims(final Map<String, Map<String, String>> claims) {
        this.claims = claims;
    }

    public int getCount() {
        return count;
    }

    public void setCount(final int count) {
        this.count = count;
    }

    public Set<String> getContacts() {
        return contacts;
    }

    public void setContacts(final Set<String> contacts) {
        this.contacts = contacts;
    }

    public boolean isGras() {
        return gras;
    }

    public void setGras(final boolean gras) {
        this.gras = gras;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(final String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public void setAuthorizationRequestParameters(final Map<String, String> parameters) {
        authorizationRequestParameters = parameters;
    }

    public String getCsrf() {
        return (String) authorizationRequest.getExtensions().get("csrf");
    }

    public Map<String, String> getAuthorizationRequestParameters() {
        return authorizationRequestParameters;
    }
}
