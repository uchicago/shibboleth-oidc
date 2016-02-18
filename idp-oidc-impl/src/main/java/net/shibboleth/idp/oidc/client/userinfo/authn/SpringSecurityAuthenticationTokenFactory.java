package net.shibboleth.idp.oidc.client.userinfo.authn;


import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.oidc.OIDCException;
import net.shibboleth.idp.oidc.config.OIDCConstants;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

public final class SpringSecurityAuthenticationTokenFactory {
    private static final Logger log = LoggerFactory.getLogger(SpringSecurityAuthenticationTokenFactory.class);

    public static Authentication buildAuthentication(final ProfileRequestContext profileRequestContext) {
        final SubjectContext principal = profileRequestContext.getSubcontext(SubjectContext.class);

        if (principal == null || principal.getPrincipalName() == null) {
            throw new OIDCException("No SubjectContext found in the profile request context");
        }

        /**
         * Grab the authentication context class ref and classify it as an authority to be used later
         * by custom token services to generate acr and amr claims.
         *
         * MitreID connect can only work with SimpleGrantedAuthority. So here we are creating specific authority
         * instances first and then converting them to SimpleGrantedAuthority. The role could be parsed later to
         * locate and reconstruct the actual instance.
         */
        final Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new SimpleGrantedAuthority(OIDCConstants.ROLE_USER));
        
        final AuthenticationContext authCtx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (authCtx != null) {
            log.debug("Found an authentication context in the profile request context");

            final RequestedPrincipalContext principalContext = authCtx.getSubcontext(RequestedPrincipalContext.class);
            if (principalContext != null && principalContext.getMatchingPrincipal() != null) {
                log.debug("Found an requested principal context context in the profile request context with matching principal {}",
                        principalContext.getMatchingPrincipal().getName());

                final AuthenticationClassRefAuthority authority = new AuthenticationClassRefAuthority(
                        principalContext.getMatchingPrincipal().getName());

                log.debug("Adding authority {}", authority.getAuthority());
                authorities.add(new SimpleGrantedAuthority(authority.toString()));
            }
            if (authCtx.getAuthenticationResult() != null) {
                final AuthenticationMethodRefAuthority authority = new AuthenticationMethodRefAuthority(
                        authCtx.getAuthenticationResult().getAuthenticationFlowId());
                log.debug("Adding authority {}", authority.getAuthority());
                authorities.add(new SimpleGrantedAuthority(authority.toString()));
            }
        }

        /**
         * Note that Spring Security loses the details object when it attempts to grab onto the authentication
         * object that is combined, when codes are asking to create access tokens.
         */
        final User user = new User(principal.getPrincipalName(), UUID.randomUUID().toString(),
                Collections.singleton(new SimpleGrantedAuthority(OIDCConstants.ROLE_USER)));

        log.debug("Created user details object for {} with authorities {}", user.getUsername(), user.getAuthorities());

        final SpringSecurityAuthenticationToken authenticationToken =
                new SpringSecurityAuthenticationToken(profileRequestContext, authorities);
        log.debug("Final authentication token authorities are {}", authorities);

        authenticationToken.setAuthenticated(true);
        authenticationToken.setDetails(user);
        return authenticationToken;
    }
}
