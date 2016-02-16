package net.shibboleth.idp.oidc.client.userinfo.authn;

import org.springframework.security.core.GrantedAuthority;

public class AuthenticationMethodRefAuthority implements GrantedAuthority {
    private final String authority;

    public AuthenticationMethodRefAuthority(final String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return this.authority;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + ',' + this.authority;
    }

    public static AuthenticationMethodRefAuthority getAuthenticationClassRefAuthority(final GrantedAuthority authority) {
        final String typeAndRole = authority.toString();
        if (typeAndRole.contains(AuthenticationMethodRefAuthority.class.getSimpleName())) {
            final String role = typeAndRole.split(",")[1];
            return new AuthenticationMethodRefAuthority(role);
        }
        return null;
    }
}
