package net.shibboleth.idp.oidc.endpoints;

/**
 * Represents the initial login endpoint for openid connect.
 * This point, this class is very much silent as the endpoint
 * handling is done by Spring Security.
 */
public final class AuthorizeEndpoint {
    /** URL endpoint for authorization used to map requests. */
    public static final String URL = "/oidc/authorize";

    /**
     * Instantiates a new authZ endpoint.
     */
    private AuthorizeEndpoint() {}
}


