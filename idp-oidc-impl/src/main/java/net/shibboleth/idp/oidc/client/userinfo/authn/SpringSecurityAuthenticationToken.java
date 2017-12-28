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

import net.shibboleth.idp.authn.context.SubjectContext;
import org.joda.time.DateTime;
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

    private final Object credentials;
    private final Object principal;
    private final DateTime authenticationDateTime;

    /**
     * Instantiates a new Spring security authentication token.
     *
     * @param prc                    the prc
     * @param authorities            the authorities
     * @param principal
     * @param authenticationDateTime
     */
    SpringSecurityAuthenticationToken(final Collection<GrantedAuthority> authorities,
                                      final Object credentials, final Object principal, final DateTime authenticationDateTime) {
        super(authorities);
        this.credentials = credentials;
        this.principal = principal;
        this.authenticationDateTime = authenticationDateTime;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public String getName() {
        final SubjectContext principal = (SubjectContext) getPrincipal();
        return principal.getPrincipalName();
    }

    public DateTime getAuthenticationDateTime() {
        return authenticationDateTime;
    }
}
