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
 * Indicates the initial OpenIdConnect response that is send back to the
 * application when an access token is generated.
 */
public class OpenIdConnectResponse {

    /**
     * The Redirect uri.
     */
    private String redirectUri;

    /**
     * The Authorization request.
     */
    private AuthorizationRequest authorizationRequest;

    /**
     * The Client.
     */
    private ClientDetailsEntity client;

    /**
     * The Scopes.
     */
    private Set<SystemScope> scopes = new LinkedHashSet<>();

    /**
     * The Claims.
     */
    private Map<String, Map<String, String>> claims = new LinkedHashMap<>();

    /**
     * The Count.
     */
    private int count;

    /**
     * The Contacts.
     */
    private Set<String> contacts = new HashSet<>();

    /**
     * The Authorization request parameters.
     */
    private Map<String, String> authorizationRequestParameters;

    /**
     * The Gras.
     */
    private boolean gras;

    /**
     * Gets authorization request.
     *
     * @return the authorization request
     */
    public AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    /**
     * Sets authorization request.
     *
     * @param authZRequest the authorization request
     */
    public void setAuthorizationRequest(final AuthorizationRequest authZRequest) {
        this.authorizationRequest = authZRequest;
    }

    /**
     * Gets client.
     *
     * @return the client
     */
    public ClientDetailsEntity getClient() {
        return client;
    }

    /**
     * Sets client.
     *
     * @param clientEntity the client
     */
    public void setClient(final ClientDetailsEntity clientEntity) {
        this.client = clientEntity;
    }

    /**
     * Gets scopes.
     *
     * @return the scopes
     */
    public Set<SystemScope> getScopes() {
        return scopes;
    }

    /**
     * Sets scopes.
     *
     * @param scopesSet the scopes
     */
    public void setScopes(final Set<SystemScope> scopesSet) {
        this.scopes = scopesSet;
    }

    /**
     * Gets claims.
     *
     * @return the claims
     */
    public Map<String, Map<String, String>> getClaims() {
        return claims;
    }

    /**
     * Sets claims.
     *
     * @param claimsSet the claims
     */
    public void setClaims(final Map<String, Map<String, String>> claimsSet) {
        this.claims = claimsSet;
    }

    /**
     * Gets count.
     *
     * @return the count
     */
    public int getCount() {
        return count;
    }

    /**
     * Sets count.
     *
     * @param cnt the count
     */
    public void setCount(final int cnt) {
        this.count = cnt;
    }

    /**
     * Gets contacts.
     *
     * @return the contacts
     */
    public Set<String> getContacts() {
        return contacts;
    }

    /**
     * Sets contacts.
     *
     * @param contactsSet the contacts
     */
    public void setContacts(final Set<String> contactsSet) {
        this.contacts = contactsSet;
    }

    /**
     * is generally regarded as safe.
     *
     * @return the boolean
     */
    public boolean isGras() {
        return gras;
    }

    /**
     * Sets gras.
     *
     * @param isgras the gras
     */
    public void setGras(final boolean isgras) {
        this.gras = isgras;
    }

    /**
     * Gets redirect uri.
     *
     * @return the redirect uri
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Sets redirect uri.
     *
     * @param uri the redirect uri
     */
    public void setRedirectUri(final String uri) {
        this.redirectUri = uri;
    }

    /**
     * Sets authorization request parameters.
     *
     * @param parameters the parameters
     */
    public void setAuthorizationRequestParameters(final Map<String, String> parameters) {
        authorizationRequestParameters = parameters;
    }

    /**
     * Gets csrf.
     *
     * @return the csrf
     */
    public String getCsrf() {
        return (String) authorizationRequest.getExtensions().get("csrf");
    }

    /**
     * Gets authorization request parameters.
     *
     * @return the authorization request parameters
     */
    public Map<String, String> getAuthorizationRequestParameters() {
        return authorizationRequestParameters;
    }
}
