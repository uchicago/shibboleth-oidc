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
package net.shibboleth.idp.oidc.client.userinfo.authn.authority;

import org.springframework.security.core.GrantedAuthority;

/**
 * The type Authentication class ref authority.
 */
public class AuthenticationClassRefAuthority implements GrantedAuthority {
    private static final long serialVersionUID = -2973724746234368470L;
    
    /**
     * The Authority.
     */
    private final String authority;

    /**
     * Instantiates a new Authentication class ref authority.
     *
     * @param auth the auth
     */
    public AuthenticationClassRefAuthority(final String auth) {
        this.authority = auth;
    }

    @Override
    public String getAuthority() {
        return this.authority;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + ',' + this.authority;
    }

    /**
     * Gets authentication class ref authority.
     *
     * @param authority the authority
     * @return the authentication class ref authority
     */
    public static AuthenticationClassRefAuthority getAuthenticationClassRefAuthority(final GrantedAuthority authority) {
        final String typeAndRole = authority.toString();
        if (typeAndRole.contains(AuthenticationClassRefAuthority.class.getSimpleName())) {
            final String role = typeAndRole.split(",")[1];
            return new AuthenticationClassRefAuthority(role);
        }
        return null;
    }

}
