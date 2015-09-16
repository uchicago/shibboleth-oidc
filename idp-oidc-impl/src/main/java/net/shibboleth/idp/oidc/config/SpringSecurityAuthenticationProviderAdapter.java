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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * A wrapper component for Spring security's authentication provider
 * that is able to produce authentication objects based on the authentication
 * context provided by the identity provider.
 */
@Component("authenticationProviderAdapter")
public class SpringSecurityAuthenticationProviderAdapter implements AuthenticationProvider {

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final SpringSecurityAuthenticationToken token = (SpringSecurityAuthenticationToken) authentication;
        return token.buildAuthentication();
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return SpringSecurityAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
