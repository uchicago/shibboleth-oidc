package net.shibboleth.idp.oidc.config;

import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
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
        if (token.getPrincipal() != null) {

            final UsernamePasswordContext context = (UsernamePasswordContext) token.getCredentials();

            final SpringSecurityAuthenticationToken authenticationToken =
                    new SpringSecurityAuthenticationToken(token.getProfileRequestContext());

            authenticationToken.setAuthenticated(true);
            authenticationToken.setDetails(new User(context.getUsername(),
                    context.getPassword(), token.getAuthorities()));
            return authenticationToken;
        }
        throw new InsufficientAuthenticationException("No authenticated principal found");
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return SpringSecurityAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
