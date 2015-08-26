package net.shibboleth.idp.oidc.config;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collections;

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
        AuthenticationContext ctx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        UsernamePasswordContext upCtx = ctx.getSubcontext(UsernamePasswordContext.class);
        return upCtx;
    }

    @Override
    public Object getPrincipal() {
        AuthenticationContext ctx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        Subject subject = ctx.getAuthenticationResult().getSubject();
        return subject;
    }


    public ProfileRequestContext getProfileRequestContext() {
        return profileRequestContext;
    }
}
