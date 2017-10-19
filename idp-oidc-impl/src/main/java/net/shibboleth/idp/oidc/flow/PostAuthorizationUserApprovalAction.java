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
package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.oidc.OIDCException;
import net.shibboleth.idp.oidc.util.OIDCUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    /**
     * The Log.
     */
    private final Logger log = LoggerFactory.getLogger(PostAuthorizationUserApprovalAction.class);

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        final HttpServletRequest request = OIDCUtils.getHttpServletRequest(springRequestContext);
        if (request == null) {
            throw new OIDCException("HttpServletRequest cannot be null");
        }

        final OIDCAuthorizationRequestContext authZContext =
                profileRequestContext.getSubcontext(OIDCAuthorizationRequestContext.class);
        if (authZContext == null) {
            log.warn("No authorization request could be located in the profile request context");
            return Events.Failure.event(this);
        }

        final OIDCAuthorizationResponseContext responseCtx =
                profileRequestContext.getSubcontext(OIDCAuthorizationResponseContext.class);
        if (responseCtx == null) {
            log.warn("No response context could be located in the profile request context");
            return Events.Failure.event(this);
        }
        final Object csrf = request.getAttribute("_csrf");
        if (csrf == null) {
            log.warn("CSRF attribute could not be found in the request");
            return Events.Failure.event(this);
        }

        final Map map = new HashMap<>();
        map.put("_csrf", csrf);
        OIDCUtils.putAuthorizationRequestIntoScope(authZContext.getAuthorizationRequest(), springRequestContext.getViewScope());
        OIDCUtils.putOIDCResponseIntoScope(responseCtx.getOidcResponse(), springRequestContext.getViewScope());
        OIDCUtils.putPostAuthorizationAttributesIntoScope(map, springRequestContext.getViewScope());
        OIDCUtils.putCsrfIntoScope(csrf, springRequestContext.getViewScope());


        /**
         * This is required for the authorization endpoint of Spring Security, as it needs
         * the authZ request to be a session attribute.
         */
        OIDCUtils.putSessionAttribute(request, "authorizationRequest", authZContext.getAuthorizationRequest());
        final Event event = super.doExecute(springRequestContext, profileRequestContext);
        if (event == null) {
            return Events.Done.event(this);
        }
        return event;
    }
}
