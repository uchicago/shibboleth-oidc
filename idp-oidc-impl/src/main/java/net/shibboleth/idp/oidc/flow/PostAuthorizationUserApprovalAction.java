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
package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.consent.context.impl.ConsentContext;
import net.shibboleth.idp.consent.impl.Consent;
import net.shibboleth.idp.oidc.util.OpenIdConnectUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * An action to handle the user approval/consent post authorization.
 */
public class PostAuthorizationUserApprovalAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(PreAuthorizeUserApprovalAction.class);

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {

        final HttpServletRequest request = HttpServletRequestResponseContext.getRequest();
        final Map map = new HashMap<>();
        map.put("_csrf", request.getAttribute("_csrf"));

        final ConsentContext context = profileRequestContext.getSubcontext(ConsentContext.class);
        final Map<String, Consent> attributes = context.getCurrentConsents();
        final AuthorizationRequest authorizationRequest =
                OpenIdConnectUtils.getAuthorizationRequest(HttpServletRequestResponseContext.getRequest());
        final OpenIdConnectResponse response = OpenIdConnectUtils.getResponse(springRequestContext);

        springRequestContext.getViewScope().put("postAuthorizationAttributes", map);
        return super.doExecute(springRequestContext, profileRequestContext);
    }
}
