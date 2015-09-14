package net.shibboleth.idp.oidc.config;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collections;
import java.util.Set;

/**
 *
 */
public final class SpringSecurityAuthenticationToken extends AbstractAuthenticationToken {
    private ProfileRequestContext profileRequestContext;

    public SpringSecurityAuthenticationToken(final ProfileRequestContext prc) {
        super(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        this.profileRequestContext = prc;
    }

    @Override
    public Object getCredentials() {
        final AuthenticationContext ctx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        final UsernamePasswordContext upCtx = ctx.getSubcontext(UsernamePasswordContext.class);
        return upCtx;
    }

    @Override
    public Object getPrincipal() {
        final AuthenticationContext ctx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        final Subject subject = ctx.getAuthenticationResult().getSubject();
        return subject;
    }

    @Override
    public String getName() {
        final Subject subject = (Subject) getPrincipal();
        final Set<UsernamePrincipal> principal = subject.getPrincipals(UsernamePrincipal.class);
        final String name = principal.iterator().next().getName();
        return name;
    }

    public ProfileRequestContext getProfileRequestContext() {
        return profileRequestContext;
    }
}
