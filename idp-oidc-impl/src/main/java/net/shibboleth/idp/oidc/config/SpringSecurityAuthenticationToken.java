/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
 * A wrapper for an authentication object managed by Spring security
 * whose principals and credentials are produced by the identity provider.
 */
public final class SpringSecurityAuthenticationToken extends AbstractAuthenticationToken {
    /**
     * The Profile request context.
     */
    private ProfileRequestContext profileRequestContext;

    /**
     * Instantiates a new Spring security authentication token.
     *
     * @param prc the prc
     */
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
        if (principal.isEmpty()) {
            throw new RuntimeException("No user name principal could be retrieved from the subject");
        }
        final String name = principal.iterator().next().getName();
        return name;
    }

    /**
     * Gets profile request context.
     *
     * @return the profile request context
     */
    public ProfileRequestContext getProfileRequestContext() {
        return profileRequestContext;
    }
}
