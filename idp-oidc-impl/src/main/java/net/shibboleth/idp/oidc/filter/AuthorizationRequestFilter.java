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
package net.shibboleth.idp.oidc.filter;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import net.shibboleth.idp.oidc.OpenIdConnectUtils;
import org.apache.http.client.utils.URIBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.request.ConnectRequestParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authorization initial filter that is executed by Spring Security.
 * Evaluates the OpenId Connect authorization request, builds it and passes
 * it down to underlying flows.
 */
@Component("authzRequestFilter")
public class AuthorizationRequestFilter extends GenericFilterBean {
    private static final String PROFILE_OIDC_AUTHORIZE = "/profile/oidc/authorize";

    private final Logger log = LoggerFactory.getLogger(AuthorizationRequestFilter.class);

    @Autowired
    private OAuth2RequestFactory authRequestFactory;

    @Autowired
    private ClientDetailsEntityService clientService;

    @Autowired
    private RedirectResolver redirectResolver;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;


        if (determineProfilePathForExceution(request)) {
            chain.doFilter(request, response);
            return;
        }

        log.debug("Evaluating authorization request");
        try {
            log.debug("Constructing authorization request");
            Map<String, String> requestParameters = createRequestMap(request.getParameterMap());
            AuthorizationRequest authRequest = authRequestFactory.createAuthorizationRequest(requestParameters);

            if (Strings.isNullOrEmpty(authRequest.getClientId())) {
                throw new InvalidClientException("No client id is specified in the authorization request");
            }

            log.debug("Loading client by id {}", authRequest.getClientId());
            ClientDetailsEntity client = clientService.loadClientByClientId(authRequest.getClientId());
            OpenIdConnectUtils.setAuthorizationRequest(request, authRequest, requestParameters);
            log.debug("Saved authorization request");

            log.debug("Found client {}.", client.toString());
            OpenIdConnectUtils.setClient(request, client);
            log.debug("Saved client request");

            Object loginHint = authRequest.getExtensions().get(ConnectRequestParameters.LOGIN_HINT);
            if (loginHint != null) {
                OpenIdConnectUtils.setRequestParameter(request, ConnectRequestParameters.LOGIN_HINT, loginHint);
                log.debug("Saved login hint {} into session", loginHint);
            } else {
                OpenIdConnectUtils.removeRequestParameter(request, ConnectRequestParameters.LOGIN_HINT);
                log.debug("Removed login hint attribute from session");
            }

            String prompt = (String) authRequest.getExtensions().get(ConnectRequestParameters.PROMPT);
            if (prompt != null) {
                log.debug("Authorization request contains prompt {}");
                if (checkForPrompts(prompt, response, request)) {
                    chain.doFilter(req, res);
                    return;
                }
            } else if (authRequest.getExtensions().get(ConnectRequestParameters.MAX_AGE) != null ||
                    client.getDefaultMaxAge() != null) {
                log.debug("Authorization request or client configuration contains max age");
                checkForMaxAge(request);
                chain.doFilter(req, res);
            } else {
                log.debug("Evaluated authorization request. Invoking filter chain normally");
                chain.doFilter(req, res);
            }

        } catch (InvalidClientException e) {
            log.debug("Invalid client specified in the request", e);
            chain.doFilter(req, res);
        }
    }

    /**
     * Determine profile path for filter execution.
     * Ignores all request patterns that do not start
     * with {@value #PROFILE_OIDC_AUTHORIZE}.
     *
     * @param req the req
     * @param res the res
     * @param chain the chain
     * @param request the request
     * @return the boolean
     * @throws IOException the iO exception
     * @throws ServletException the servlet exception
     */
    private boolean determineProfilePathForExceution(final HttpServletRequest request)
            throws IOException, ServletException {
        String servletPath = request.getServletPath();
        String pathInfo = request.getPathInfo();
        if (Strings.isNullOrEmpty(servletPath) || Strings.isNullOrEmpty(pathInfo)) {
            log.debug("No servlet path available. Not an authorization request. Invoking filter chain");
            return true;
        }

        String path = servletPath.concat(pathInfo);
        if (!path.startsWith(PROFILE_OIDC_AUTHORIZE)) {
            log.debug("Not an authorization request. Invoking filter chain normally");
            return true;
        }
        return false;
    }

    /**
     * Check for max age. Determines max-age either from client configuration
     * or from the authorization request. Tries to figure out if an existing
     * authentication session bound to spring security is too old, and if so,
     * it will clear it out.
     *
     * @param request the request
     */
    private void checkForMaxAge(final HttpServletRequest request) {

        ClientDetailsEntity client = OpenIdConnectUtils.getClient(request);
        Integer max = client != null ? client.getDefaultMaxAge() : null;
        log.debug("Client configuration set to max age {}", max);

        AuthorizationRequest authRequest = OpenIdConnectUtils.getAuthorizationRequest(request);
        String maxAge = (String) authRequest.getExtensions().get(ConnectRequestParameters.MAX_AGE);
        log.debug("Authorization request contains max age {}", maxAge);
        if (maxAge != null) {
            max = Integer.parseInt(maxAge);
        }

        if (max != null) {
            log.debug("Evaluated max age to use as {}", max);
            Date authTime = OpenIdConnectUtils.getAuthenticationTimestamp(request);
            log.debug("Authentication time set to {}", authTime);
            Date now = new Date();
            if (authTime != null) {
                long seconds = (now.getTime() - authTime.getTime()) / 1000;
                if (seconds > max) {
                    log.debug("Authentication is too old. Clearing authentication context", authTime);
                    SecurityContextHolder.getContext().setAuthentication(null);
                }
            }
        }
        log.debug("Resuming with filter chain");
    }

    /**
     * Check for prompts in the authorization request. Evaluates
     * if redirects to the client should execute
     * or authentication cleared forcing the user
     * to authenticate again.
     *
     * @param prompt the prompt
     * @param response the response
     * @param request the request
     * @return the boolean
     * @throws IOException the IO exception
     */
    private boolean checkForPrompts(final String prompt,
                                    final HttpServletResponse response,
                                    final HttpServletRequest request)
            throws IOException {

        final ClientDetailsEntity client = OpenIdConnectUtils.getClient(request);
        final AuthorizationRequest authRequest = OpenIdConnectUtils.getAuthorizationRequest(request);

        List<String> prompts = Splitter.on(ConnectRequestParameters.PROMPT_SEPARATOR)
                    .splitToList(Strings.nullToEmpty(prompt));
        if (prompts.contains(ConnectRequestParameters.PROMPT_NONE)) {
            log.debug("Prompt contains {}", ConnectRequestParameters.PROMPT_NONE);
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (auth != null) {
                log.debug("Authentication context is empty");
            } else {
                log.info("Client requested no prompt");
                if (client != null && authRequest.getRedirectUri() != null) {
                    String url = redirectResolver.resolveRedirect(authRequest.getRedirectUri(), client);

                    try {
                        URIBuilder uriBuilder = new URIBuilder(url);

                        uriBuilder.addParameter(ConnectRequestParameters.ERROR,
                                ConnectRequestParameters.LOGIN_REQUIRED);
                        if (!Strings.isNullOrEmpty(authRequest.getState())) {
                            uriBuilder.addParameter(ConnectRequestParameters.STATE, authRequest.getState());
                        }
                        log.debug("Resolved redirect url {}", uriBuilder.toString());
                        response.sendRedirect(uriBuilder.toString());
                        return true;

                    } catch (URISyntaxException e) {
                        log.error("Can't build redirect URI for prompt=none, sending error instead", e);
                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
                        return true;
                    }
                }

                log.warn("Access denied. Either client is not found or no redirect uri is specified");
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
                return true;
            }
        } else if (prompts.contains(ConnectRequestParameters.PROMPT_LOGIN)) {
            log.debug("Prompt contains {}", ConnectRequestParameters.PROMPT_LOGIN);

            if (OpenIdConnectUtils.isRequestPrompted(request)) {
                OpenIdConnectUtils.setPromptRequested(request);

                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                if (auth != null) {
                    SecurityContextHolder.getContext().setAuthentication(null);
                    log.debug("Cleared authentication from context. Proceeding with filter chain");

                } else {
                    log.debug("Authentication is not found in the context. Proceeding with filter chain");

                }
            } else {
                OpenIdConnectUtils.removeRequestPrompted(request);
            }
        } else {
            log.debug("Prompt is not supported. Proceeding with filter chain");

        }
        return false;
    }

    /**
     * Creates a map of request parameters. Uses the first parameter value
     * in case multi-valued parameters are found
     * @param parameterMap the original request parameters map
     * @return newly built parameters map
     */
    private Map<String, String> createRequestMap(Map<String, String[]> parameterMap) {
        Map<String, String> requestMap = new HashMap<>();
        for (String key : parameterMap.keySet()) {
            String[] val = parameterMap.get(key);
            if (val != null && val.length > 0) {
                log.debug("Added request parameter {} with value {}", key, val[0]);
                requestMap.put(key, val[0]);
            }
        }

        return requestMap;
    }

}
