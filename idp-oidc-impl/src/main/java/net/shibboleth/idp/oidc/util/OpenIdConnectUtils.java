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
package net.shibboleth.idp.oidc.util;

import net.shibboleth.idp.oidc.flow.OpenIdConnectResponse;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Date;
import java.util.Map;

/**
 * OpenId Connect Utility methods that deal with setting and removing
 * session data.
 */
public final class OpenIdConnectUtils {
    /** Attribute name for the OIDC response. */
    private static final String FLOW_SCOPE_ATTRIBUTE_RESPONSE = "oidcResponse";

    /** Attribute name to store the authorization request. */
    private static final String ATTR_OIDC_AUTHZ_REQUEST = "authorizationRequest";

    /** Attribute name to store the authorization request parameters as they were received. */
    private static final String ATTR_OIDC_AUTHZ_REQUEST_PARAMETERS = "OIDC_AUTHZ_REQUEST_PARAMS";

    /** Attribute name to store the openid connect client. */
    private static final String ATTR_OIDC_CLIENT = "OIDC_CLIENT";

    /**
     * The constant PROMPTED.
     */
    private static final String PROMPTED = "PROMPT_FILTER_PROMPTED";

    /**
     * The constant PROMPT_REQUESTED.
     */
    private static final String PROMPT_REQUESTED = "PROMPT_FILTER_REQUESTED";

    /**
     * The constant LOG.
     */
    private static final Logger LOG = LoggerFactory.getLogger(OpenIdConnectUtils.class);

    /**
     * Instantiates a new Open id connect utils.
     */
    private OpenIdConnectUtils() {}

    /**
     * Gets authorization request.
     *
     * @param request the request
     * @return the authorization request
     */
    public static AuthorizationRequest getAuthorizationRequest(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        final AuthorizationRequest authorizationRequest = (AuthorizationRequest)
                session.getAttribute(ATTR_OIDC_AUTHZ_REQUEST);
        if (authorizationRequest != null) {
            LOG.debug("Authorization request found in session.");
        } else {
            LOG.debug("Authorization request not found in session.");
        }

        return authorizationRequest;
    }

    /**
     * Gets authorization request parameters.
     *
     * @param request the request
     * @return the authorization request parameters
     */
    public static Map<String, String> getAuthorizationRequestParameters(final HttpServletRequest request) {
        HttpSession session = request.getSession();
        return (Map<String, String>) session.getAttribute(ATTR_OIDC_AUTHZ_REQUEST_PARAMETERS);
    }

    /**
     * Sets authorization request.
     *
     * @param request the request
     * @param authorizationRequest the authorization request
     * @param parameterMap the parameter map
     */
    public static void setAuthorizationRequest(final HttpServletRequest request,
                                               final AuthorizationRequest authorizationRequest,
                                               final Map<String, String> parameterMap) {
        final HttpSession session = request.getSession();
        session.setAttribute(ATTR_OIDC_AUTHZ_REQUEST, authorizationRequest);
        session.setAttribute(ATTR_OIDC_AUTHZ_REQUEST_PARAMETERS, parameterMap);
    }

    public static void removeAuthorizationRequest(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        session.removeAttribute(ATTR_OIDC_AUTHZ_REQUEST);
        session.removeAttribute(ATTR_OIDC_AUTHZ_REQUEST_PARAMETERS);
    }

    /**
     * Sets client.
     *
     * @param request the request
     * @param client the client
     */
    public static void setClient(final HttpServletRequest request,
                               final ClientDetailsEntity client) {
        final HttpSession session = request.getSession();
        session.setAttribute(ATTR_OIDC_CLIENT, client);
    }

    /**
     * Gets client.
     *
     * @param request the request
     * @return the client
     */
    public static ClientDetailsEntity getClient(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        return (ClientDetailsEntity) session.getAttribute(ATTR_OIDC_CLIENT);
    }

    /**
     * Sets request parameter.
     *
     * @param request the request
     * @param parameter the parameter
     * @param value the value
     */
    public static void setRequestParameter(final HttpServletRequest request,
                                 final String parameter,
                                 final Object value) {
        final HttpSession session = request.getSession();
        session.setAttribute(parameter, value);
    }

    /**
     * Remove session parameter.
     *
     * @param request the request
     * @param parameter the parameter
     */
    public static void removeSessionAttribute(final HttpServletRequest request,
                                              final String parameter) {
        final HttpSession session = request.getSession();
        session.removeAttribute(parameter);
    }

    /**
     * Remove request prompted.
     *
     * @param request the request
     */
    public static void removeRequestPrompted(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        session.removeAttribute(PROMPTED);
    }

    /**
     * Sets prompt requested.
     *
     * @param request the request
     */
    public static void setPromptRequested(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        session.setAttribute(PROMPT_REQUESTED, Boolean.TRUE);
    }

    /**
     * Is request prompted.
     *
     * @param request the request
     * @return the boolean
     */
    public static Boolean isRequestPrompted(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        return session.getAttribute(PROMPTED) == null;
    }

    /**
     * Gets authentication timestamp.
     *
     * @param request the request
     * @return the authentication timestamp
     */
    public static Date getAuthenticationTimestamp(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        return (Date) session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP);
    }

    /**
     * Gets response.
     *
     * @param context the context
     * @return the response
     */
    public static OpenIdConnectResponse getResponse(final RequestContext context) {
        final OpenIdConnectResponse response =
                context.getFlowScope().get(FLOW_SCOPE_ATTRIBUTE_RESPONSE, OpenIdConnectResponse.class);
        return response;
    }

    /**
     * Sets response.
     *
     * @param context the context
     * @param response the response
     */
    public static void setResponse(final RequestContext context, final OpenIdConnectResponse response) {
        context.getFlowScope().put(FLOW_SCOPE_ATTRIBUTE_RESPONSE, response);
    }
}
