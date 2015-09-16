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
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import javax.security.auth.Subject;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

/**
 * A wrapper for an authentication object managed by Spring security
 * whose principals and credentials are produced by the identity provider.
 */
public final class SpringSecurityAuthenticationToken extends AbstractAuthenticationToken {
    /**
     * The Profile request context.
     */
    private final ProfileRequestContext profileRequestContext;

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

    /**
     * Gets profile request context.
     *
     * @return the profile request context
     */
    public ProfileRequestContext getProfileRequestContext() {
        return profileRequestContext;
    }


    public Authentication buildAuthentication() {
        final SubjectContext principal = (SubjectContext) getPrincipal();

        if (principal == null) {
            throw new InsufficientAuthenticationException("No SubjectContext found in the profile request context");
        }

        final SpringSecurityAuthenticationToken authenticationToken = new SpringSecurityAuthenticationToken(getProfileRequestContext());
        authenticationToken.setAuthenticated(true);
        final User user = new User(principal.getPrincipalName(), UUID.randomUUID().toString(), getAuthorities());
        authenticationToken.setDetails(user);
        return authenticationToken;
    }
}
