package net.shibboleth.idp.oidc.client.userinfo.authn;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * A wrapper component for Spring security's authentication provider
 * that is able to produce authentication objects based on the authentication
 * context provided by the identity provider.
 */
@Component("authenticationProviderAdapter")
public class SpringSecurityAuthenticationProviderAdapter implements AuthenticationProvider {

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final SpringSecurityAuthenticationToken token = (SpringSecurityAuthenticationToken) authentication;
        return token.buildAuthentication();
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return SpringSecurityAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
