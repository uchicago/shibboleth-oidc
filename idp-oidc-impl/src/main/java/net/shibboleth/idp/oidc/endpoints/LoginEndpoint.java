package net.shibboleth.idp.oidc.endpoints;

/**
 * Represents the initial login endpoint for openid connect.
 * This point, this class is very much silent as the endpoint
 * handling is done by Spring Security.
 */
public final class LoginEndpoint {
    /** URL endpoint for JWK used to map requests. */
    public static final String URL = "/oidc/login";

    /**
     * Instantiates a new Login endpoint.
     */
    private LoginEndpoint() {}
}


