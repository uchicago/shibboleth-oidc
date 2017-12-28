/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements. See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.shibboleth.idp.oidc.client.userinfo.authn;


import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.oidc.OIDCException;
import net.shibboleth.idp.oidc.client.userinfo.authn.authority.AuthenticationClassRefAuthority;
import net.shibboleth.idp.oidc.client.userinfo.authn.authority.AuthenticationMethodRefAuthority;
import net.shibboleth.idp.oidc.config.OIDCConstants;
import net.shibboleth.idp.session.context.SessionContext;
import org.joda.time.DateTime;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * The type Spring security authentication token factory.
 */
public final class SpringSecurityAuthenticationTokenFactory {
    /**
     * The constant LOG.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SpringSecurityAuthenticationTokenFactory.class);

    /**
     * Instantiates a new Spring security authentication token factory.
     */
    private SpringSecurityAuthenticationTokenFactory() {
    }

    /**
     * Build authentication authentication.
     *
     * @param profileRequestContext the profile request context
     * @param client                the client
     * @return the authentication
     */
    public static Authentication buildAuthentication(final ProfileRequestContext profileRequestContext,
                                                     final ClientDetailsEntity client) {
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
        authorities.add(new SimpleGrantedAuthority(OIDCConstants.ROLE_CLIENT + "_" + client.getClientId()));

        final AuthenticationContext authCtx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (authCtx != null) {
            LOG.debug("Found an authentication context in the profile request context");

            final RequestedPrincipalContext principalContext = authCtx.getSubcontext(RequestedPrincipalContext.class);
            if (principalContext != null && principalContext.getMatchingPrincipal() != null) {
                LOG.debug("Found requested principal context context with matching principal {}",
                    principalContext.getMatchingPrincipal().getName());

                final AuthenticationClassRefAuthority authority = new AuthenticationClassRefAuthority(
                    principalContext.getMatchingPrincipal().getName());

                LOG.debug("Adding authority {}", authority.getAuthority());
                authorities.add(new SimpleGrantedAuthority(authority.toString()));
            }
            if (authCtx.getAuthenticationResult() != null) {
                final AuthenticationMethodRefAuthority authority = new AuthenticationMethodRefAuthority(
                    authCtx.getAuthenticationResult().getAuthenticationFlowId());
                LOG.debug("Adding authority {}", authority.getAuthority());
                authorities.add(new SimpleGrantedAuthority(authority.toString()));
            }
        }

        /**
         * Note that Spring Security loses the details object when it attempts to grab onto the authentication
         * object that is combined, when codes are asking to create access tokens.
         */
        final User user = new User(principal.getPrincipalName(), UUID.randomUUID().toString(),
            Collections.singleton(new SimpleGrantedAuthority(OIDCConstants.ROLE_USER)));

        LOG.debug("Created user details object for {} with authorities {}", user.getUsername(), user.getAuthorities());

        final SpringSecurityAuthenticationToken authenticationToken =
            new SpringSecurityAuthenticationToken(authorities,
                getAuthenticationTokenCredentials(profileRequestContext),
                getAuthenticationTokenPrincipal(profileRequestContext),
                getAuthenticationDateTime(profileRequestContext));
        LOG.debug("Final authentication token authorities are {}", authorities);

        authenticationToken.setAuthenticated(true);
        authenticationToken.setDetails(user);
        return authenticationToken;
    }

    private static Object getAuthenticationTokenPrincipal(final ProfileRequestContext profileRequestContext) {
        return profileRequestContext.getSubcontext(SubjectContext.class);
    }

    private static Object getAuthenticationTokenCredentials(final ProfileRequestContext profileRequestContext) {
        final AuthenticationContext ctx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (ctx != null && ctx.containsSubcontext(UsernamePasswordContext.class)) {
            final UsernamePasswordContext subcontext = ctx.getSubcontext(UsernamePasswordContext.class);
            return subcontext.getUsername();
        }
        final SubjectContext sub = profileRequestContext.getSubcontext(SubjectContext.class);
        if (sub == null) {
            throw new OIDCException("Could not locate SubjectContext in the ProfileRequestContext");
        }
        return sub.getPrincipalName();
    }

    /**
     * Gets authentication date time.
     *
     * @return the authentication date time
     */
    private static DateTime getAuthenticationDateTime(final ProfileRequestContext profileRequestContext) {
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
