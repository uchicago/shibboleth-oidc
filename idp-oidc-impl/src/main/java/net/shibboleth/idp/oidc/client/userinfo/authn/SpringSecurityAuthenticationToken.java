package net.shibboleth.idp.oidc.client.userinfo.authn;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;
import java.util.UUID;

/**
 * A wrapper for an authentication object managed by Spring security
 * whose principals and credentials are produced by the identity provider.
 */
public final class SpringSecurityAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = -2135545230898461250L;

    private final ProfileRequestContext profileRequestContext;

    public SpringSecurityAuthenticationToken(final ProfileRequestContext prc) {
        super(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        this.profileRequestContext = prc;
    }

    @Override
    public Object getCredentials() {
        final AuthenticationContext ctx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (ctx != null) {
            return ctx.getSubcontext(UsernamePasswordContext.class);
        }
        return null;
    }

    @Override
    public Object getPrincipal() {
        return profileRequestContext.getSubcontext(SubjectContext.class);
    }

    @Override
    public String getName() {
        final SubjectContext principal = (SubjectContext) getPrincipal();
        return principal.getPrincipalName();
    }

    public ProfileRequestContext getProfileRequestContext() {
        return profileRequestContext;
    }

    public Authentication buildAuthentication() {
        final SubjectContext principal = (SubjectContext) getPrincipal();

        if (principal == null || principal.getPrincipalName() == null) {
            throw new InsufficientAuthenticationException("No SubjectContext found in the profile request context");
        }

        final SpringSecurityAuthenticationToken authenticationToken =
                new SpringSecurityAuthenticationToken(getProfileRequestContext());
        authenticationToken.setAuthenticated(true);
        final User user = new User(principal.getPrincipalName(), UUID.randomUUID().toString(), getAuthorities());
        authenticationToken.setDetails(user);
        return authenticationToken;
    }
}
