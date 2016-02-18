package net.shibboleth.idp.oidc.client.userinfo.authn;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.oidc.OIDCException;
import net.shibboleth.idp.session.context.SessionContext;
import org.joda.time.DateTime;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * A wrapper for an authentication object managed by Spring security
 * whose principals and credentials are produced by the identity provider.
 */
public final class SpringSecurityAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = -2135545230898461250L;

    private final ProfileRequestContext profileRequestContext;

    SpringSecurityAuthenticationToken(final ProfileRequestContext prc,
                                      final Collection<GrantedAuthority> authorities) {
        super(authorities);
        this.profileRequestContext = prc;
    }

    @Override
    public Object getCredentials() {
        final AuthenticationContext ctx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (ctx != null) {
            return ctx.getSubcontext(UsernamePasswordContext.class).getUsername();
        }
        final SubjectContext sub = profileRequestContext.getSubcontext(SubjectContext.class);
        return sub.getPrincipalName();
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

    public DateTime getAuthenticationDateTime() {
        final AuthenticationContext ctx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (ctx != null && ctx.getAuthenticationResult() != null) {
            return new DateTime(ctx.getAuthenticationResult().getAuthenticationInstant());
        }
        final SessionContext ctxSession = profileRequestContext.getSubcontext(SessionContext.class);
        if (ctxSession != null && ctxSession.getIdPSession() != null) {
            return new DateTime(ctxSession.getIdPSession().getCreationInstant());
        }
        throw new OIDCException("Could not determine authentication time based on authentication or session context");
    }

}
