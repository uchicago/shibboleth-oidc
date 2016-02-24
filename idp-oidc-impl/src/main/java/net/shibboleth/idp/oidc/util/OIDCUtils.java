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
package net.shibboleth.idp.oidc.util;

import net.shibboleth.idp.oidc.endpoints.AuthorizeEndpoint;
import net.shibboleth.idp.oidc.endpoints.DynamicRegistrationEndpoint;
import net.shibboleth.idp.oidc.endpoints.IntrospectionEndpoint;
import net.shibboleth.idp.oidc.endpoints.JWKPublishingEndpoint;
import net.shibboleth.idp.oidc.endpoints.RevocationEndpoint;
import net.shibboleth.idp.oidc.endpoints.TokenEndpoint;
import net.shibboleth.idp.oidc.endpoints.UserInfoEndpoint;
import net.shibboleth.idp.oidc.flow.OIDCResponse;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.ui.Model;
import org.springframework.util.Assert;
import org.springframework.webflow.context.servlet.ServletExternalContext;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * OpenId Connect Utility methods that deal with setting and removing
 * session data.
 */
public final class OIDCUtils {
    /**
     * Instantiates a new Open id connect utils.
     */
    private OIDCUtils() {
    }

    /**
     * Remove session parameter.
     *
     * @param request   the request
     * @param parameter the parameter
     */
    public static void removeSessionAttribute(final HttpServletRequest request,
                                              final String parameter) {
        final HttpSession session = request.getSession();
        session.removeAttribute(parameter);
    }

    /**
     * Put session attribute.
     *
     * @param request   the request
     * @param parameter the parameter
     * @param value     the value
     */
    public static void putSessionAttribute(final HttpServletRequest request,
                                           final String parameter,
                                           final Object value) {
        final HttpSession session = request.getSession();
        session.setAttribute(parameter, value);
    }

    /**
     * Gets session attribute.
     *
     * @param request   the request
     * @param parameter the parameter
     * @return the session attribute
     */
    public static Object getSessionAttribute(final HttpServletRequest request,
                                             final String parameter) {
        final HttpSession session = request.getSession();
        return session.getAttribute(parameter);
    }

    /**
     * Gets the http servlet response from the context.
     *
     * @param context the context
     * @return the http servlet response
     */
    public static HttpServletResponse getHttpServletResponse(final RequestContext context) {
        Assert.isInstanceOf(ServletExternalContext.class, context.getExternalContext(),
                "Cannot obtain HttpServletResponse from event of type: " 
                        + context.getExternalContext().getClass().getName());
        return (HttpServletResponse) context.getExternalContext().getNativeResponse();
    }

    /**
     * Gets the http servlet request from the context.
     *
     * @param context the context
     * @return the http servlet request
     */
    public static HttpServletRequest getHttpServletRequest(final RequestContext context) {
        Assert.isInstanceOf(ServletExternalContext.class, context.getExternalContext(),
                "Cannot obtain HttpServletRequest from event of type: " 
                        + context.getExternalContext().getClass().getName());

        return (HttpServletRequest) context.getExternalContext().getNativeRequest();
    }

    /**
     * Build oidc server configuration model for discovery map.
     *
     * @param model the model
     * @return the map
     */
    public static Map<String, Object> buildOidcServerConfigurationModelForDiscovery(final Model model) {
        final Map<String, Object> m = Map.class.cast(model.asMap().get("entity"));
        final String baseUrl = m.get("issuer").toString();
        m.put("authorization_endpoint", baseUrl + "profile" + AuthorizeEndpoint.URL);
        m.put("token_endpoint", baseUrl + "profile" + TokenEndpoint.URL);
        m.put("userinfo_endpoint", baseUrl + "profile" + UserInfoEndpoint.URL);
        m.put("jwks_uri", baseUrl + "profile" + JWKPublishingEndpoint.URL);
        m.put("revocation_endpoint", baseUrl + "profile" + RevocationEndpoint.URL);
        m.put("introspection_endpoint", baseUrl + "profile" + IntrospectionEndpoint.URL);
        m.put("registration_endpoint", baseUrl + "profile" + DynamicRegistrationEndpoint.URL);
        m.remove("service_documentation");
        m.remove("op_policy_uri");
        m.remove("op_tos_uri");
        return m;
    }


    /**
     * Put post authorization attributes into view scope.
     *
     * @param attributes the attributes
     * @param context    the context
     */
    public static void putPostAuthorizationAttributesIntoScope(final Map attributes, final MutableAttributeMap context) {
        context.put("postAuthorizationAttributes", attributes);
    }

    /**
     * Put authorization request into view scope.
     *
     * @param authorizationRequest the authorization request
     * @param context              the context
     */
    public static void putAuthorizationRequestIntoScope(final AuthorizationRequest authorizationRequest,
                                                        final MutableAttributeMap context) {
        context.put("authorizationRequest", authorizationRequest);
    }

    /**
     * Put oidc response into view scope.
     *
     * @param response the response
     * @param context  the context
     */
    public static void putOIDCResponseIntoScope(final OIDCResponse response, final MutableAttributeMap context) {
        context.put("oidcResponse", response);
    }

    /**
     * Put csrf into view scope.
     *
     * @param csrf    the csrf
     * @param context the context
     */
    public static void putCsrfIntoScope(final Object csrf, final MutableAttributeMap context) {
        context.put("csrf", csrf);
    }
}
