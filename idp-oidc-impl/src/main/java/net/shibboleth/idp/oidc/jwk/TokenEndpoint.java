package net.shibboleth.idp.oidc.jwk;

/**
 * Represents the initial login endpoint for openid connect.
 * This point, this class is very much silent as the endpoint
 * handling is done by Spring Security.
 */
public final class TokenEndpoint {
    /** URL endpoint for issuing tokens used to map requests. */
    public static final String URL = "/oidc/token";

    /**
     * Instantiates a new token endpoint.
     */
    private TokenEndpoint() {}
}


