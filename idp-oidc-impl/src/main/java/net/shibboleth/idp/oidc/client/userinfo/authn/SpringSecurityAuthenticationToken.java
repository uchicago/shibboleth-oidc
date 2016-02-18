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
    /**
     * The constant serialVersionUID.
     */
    private static final long serialVersionUID = -2135545230898461250L;

    /**
     * The Profile request context.
     */
    private final ProfileRequestContext profileRequestContext;

    /**
     * Instantiates a new Spring security authentication token.
     *
     * @param prc         the prc
     * @param authorities the authorities
     */
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

    /**
     * Gets profile request context.
     *
     * @return the profile request context
     */
    public ProfileRequestContext getProfileRequestContext() {
        return profileRequestContext;
    }

    /**
     * Gets authentication date time.
     *
     * @return the authentication date time
     */
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
