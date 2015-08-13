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

import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import net.shibboleth.idp.authn.config.AuthenticationProfileConfiguration;
import net.shibboleth.idp.profile.config.AbstractProfileConfiguration;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import javax.annotation.Nonnull;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class LoginConfiguration extends AbstractProfileConfiguration implements AuthenticationProfileConfiguration {
    public static final String PROFILE_ID = "http://openid.net/connect/login";

    @Nonnull
    @NonnullElements
    private Set<String> authenticationFlows = Collections.emptySet();
    @Nonnull
    @NonnullElements
    private List<String> postAuthenticationFlows = Collections.emptyList();
    @Nonnull
    @NonnullElements
    private List<AuthnContextClassRefPrincipal> defaultAuthenticationContexts = Collections.emptyList();
    @Nonnull
    @NonnullElements
    private List<String> nameIDFormatPrecedence = Collections.emptyList();

    public LoginConfiguration() {
        super(PROFILE_ID);
    }

    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<Principal> getDefaultAuthenticationMethods() {
        return ImmutableList.copyOf(this.defaultAuthenticationContexts);
    }

    public void setDefaultAuthenticationMethods(@Nonnull @NonnullElements List<AuthnContextClassRefPrincipal> contexts) {
        Constraint.isNotNull(contexts, "List of contexts cannot be null");
        this.defaultAuthenticationContexts = new ArrayList(Collections2.filter(contexts, Predicates.notNull()));
    }

    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public Set<String> getAuthenticationFlows() {
        return ImmutableSet.copyOf(this.authenticationFlows);
    }

    public void setAuthenticationFlows(@Nonnull @NonnullElements Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");
        this.authenticationFlows = new HashSet(Collections2.filter(flows, Predicates.notNull()));
    }

    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getPostAuthenticationFlows() {
        return this.postAuthenticationFlows;
    }

    public void setPostAuthenticationFlows(@Nonnull @NonnullElements Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");
        this.postAuthenticationFlows = new ArrayList(StringSupport.normalizeStringCollection(flows));
    }

    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getNameIDFormatPrecedence() {
        return ImmutableList.copyOf(this.nameIDFormatPrecedence);
    }

    public void setNameIDFormatPrecedence(@Nonnull @NonnullElements List<String> formats) {
        Constraint.isNotNull(formats, "List of formats cannot be null");
        this.nameIDFormatPrecedence = new ArrayList(Collections2.filter(formats, Predicates.notNull()));
    }
}
