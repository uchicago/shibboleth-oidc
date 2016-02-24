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

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import net.shibboleth.idp.oidc.OIDCException;
import net.shibboleth.idp.oidc.util.OIDCUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.collection.Pair;
import org.apache.http.client.utils.URIBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.request.ConnectRequestParameters;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Builds an oidc authZ context message from an incoming request.
 */
public class BuildAuthorizationRequestContextAction extends AbstractProfileAction {
    /**
     * The Log.
     */
    private final Logger log = LoggerFactory.getLogger(BuildAuthorizationRequestContextAction.class);

    /**
     * The Auth request factory.
     */
    @Autowired
    private OAuth2RequestFactory authRequestFactory;

    /**
     * The Client service.
     */
    @Autowired
    private ClientDetailsEntityService clientService;

    /**
     * The Redirect resolver.
     */
    @Autowired
    private RedirectResolver redirectResolver;

    /**
     * Instantiates a new authentication context action.
     */
    public BuildAuthorizationRequestContextAction() {
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        final HttpServletRequest request = OIDCUtils.getHttpServletRequest(springRequestContext);
        if (request == null) {
            throw new OIDCException("HttpServletRequest cannot be null");
        }

        final HttpServletResponse response = OIDCUtils.getHttpServletResponse(springRequestContext);
        if (response == null) {
            throw new OIDCException("HttpServletRequest cannot be null");
        }

        final AuthorizationRequest authorizationRequest = createAuthorizationRequest(request);
        if (Strings.isNullOrEmpty(authorizationRequest.getClientId())) {
            throw new OIDCException("No client id is specified in the authorization request");
        }


        final OIDCAuthorizationRequestContext authZContext = new OIDCAuthorizationRequestContext();
        authZContext.setAuthorizationRequest(authorizationRequest);

        if (authZContext.isImplicitResponseType() && Strings.isNullOrEmpty(authZContext.getNonce())) {
            log.error("{} is required since the requesting flow is implicit");
            throw new OIDCException("{} is required when handling implicit response type");  
        }
        
        final ClientDetailsEntity client = loadClientObject(authZContext);
        ensureRedirectUriIsAuthorized(authorizationRequest, client);
        
        log.debug("Found client {}.", client.getClientId());
        
        processLoginHintParameterIfNeeded(request, authZContext);

        Pair<Events, ? extends Object> pairEvent = new Pair<>(Events.Success, null);
        final String prompt = (String) authorizationRequest.getExtensions().get(ConnectRequestParameters.PROMPT);
        if (prompt != null) {
            log.debug("Authorization request contains prompt {}", prompt);
            pairEvent = checkForPrompts(prompt, request, client, authZContext);
        }

        return produceFinalEvent(profileRequestContext, response, authZContext, pairEvent);
    }

    /**
     * Ensure redirect uri is authorized.
     *
     * @param authorizationRequest the authorization request
     * @param client               the client
     */
    private void ensureRedirectUriIsAuthorized(final AuthorizationRequest authorizationRequest, 
                                               final ClientDetailsEntity client) {
        if (!Strings.isNullOrEmpty(authorizationRequest.getRedirectUri())) {
            boolean found = false;
            final Iterator<String> it = client.getRedirectUris().iterator();

            while (!found && it.hasNext()) {
                found = it.next().equals(authorizationRequest.getRedirectUri());
            }
            if (!found) {
                throw new OIDCException("Redirect uri in the authorization request " +
                        authorizationRequest.getRedirectUri()
                        + " is not registered for client " + client.getClientId());
            }
        }
    }

    /**
     * Produce final event event.
     *
     * @param profileRequestContext the profile request context
     * @param response              the response
     * @param authorizationRequest  the authorization request
     * @param pairEvent             the pair event
     * @return the event
     */
    private Event produceFinalEvent(final ProfileRequestContext profileRequestContext,
                                    final HttpServletResponse response,
                                    final OIDCAuthorizationRequestContext authorizationRequest,
                                    final Pair<Events, ? extends Object> pairEvent) {

        try {
            if (pairEvent.getFirst() == null) {
                log.error("Could not determine the final event based on authorization request");
                return Events.BadRequest.event(this);
            }

            switch (pairEvent.getFirst()) {
                case Failure:
                    log.error("Failed to process authorization request. Sending back response error");
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
                    break;
                case Redirect:
                    if (pairEvent.getSecond() != null) {
                        log.debug("Authorization request indicated a redirect event to {}", pairEvent.getSecond());
                        response.sendRedirect(pairEvent.getSecond().toString());
                    } else {
                        throw new OIDCException("No redirect url could be found based on the request");
                    }
                    break;
                case Success:
                    log.debug("Success. Proceeding with building the authorization context based on the request");
                    profileRequestContext.addSubcontext(authorizationRequest, true);
                    break;
                default:
                    log.debug("Proceeding to final event");
            }
            final Event ev = pairEvent.getFirst().event(this);
            log.debug("Returning final event {}", ev.getId());
            return ev;
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
            throw new OIDCException(e);
        }
    }

    /**
     * Load client object client details entity.
     *
     * @param authorizationRequest the authorization request
     * @return the client details entity
     */
    private ClientDetailsEntity loadClientObject(final OIDCAuthorizationRequestContext authorizationRequest) {
        log.debug("Loading client by id {}", authorizationRequest.getClientId());
        return clientService.loadClientByClientId(authorizationRequest.getClientId());
    }

    /**
     * Process login hint parameter if needed.
     *
     * @param request              the request
     * @param authorizationRequest the authorization request
     */
    private void processLoginHintParameterIfNeeded(final HttpServletRequest request,
                                                   final OIDCAuthorizationRequestContext authorizationRequest) {
        final Object loginHint = authorizationRequest.getLoginHint();
        if (loginHint != null) {
            OIDCUtils.putSessionAttribute(request, ConnectRequestParameters.LOGIN_HINT, loginHint);
            log.debug("Saved login hint {} into session", loginHint);
        } else {
            OIDCUtils.removeSessionAttribute(request, ConnectRequestParameters.LOGIN_HINT);
            log.debug("Removed login hint attribute from session");
        }
    }

    /**
     * Create authorization request authorization request.
     *
     * @param request the request
     * @return the authorization request
     */
    private AuthorizationRequest createAuthorizationRequest(final HttpServletRequest request) {
        log.debug("Constructing authorization request");
        final Map<String, String> requestParameters = createRequestMap(request.getParameterMap());
        return authRequestFactory.createAuthorizationRequest(requestParameters);
    }

    /**
     * Check for prompts in the authorization request. Evaluates
     * if redirects to the client should execute
     * or authentication cleared forcing the user
     * to authenticate again.
     *
     * @param prompt      the prompt
     * @param request     the request
     * @param client      the client
     * @param authRequest the auth request
     * @return the event
     * @throws java.io.IOException the IO exception
     */
    private Pair<Events, ? extends Object> checkForPrompts(final String prompt,
                                                           final HttpServletRequest request,
                                                           final ClientDetailsEntity client,
                                                           final OIDCAuthorizationRequestContext authRequest) {

        final List<String> prompts = Splitter.on(ConnectRequestParameters.PROMPT_SEPARATOR)
                .splitToList(Strings.nullToEmpty(prompt));
        if (prompts.contains(ConnectRequestParameters.PROMPT_NONE)) {
            return checkForNonePrompt(client, authRequest);
        }

        if (prompts.contains(ConnectRequestParameters.PROMPT_LOGIN)) {
            log.debug("Prompt contains {} which will require forced authN", ConnectRequestParameters.PROMPT_LOGIN);
            SecurityContextHolder.clearContext();
            authRequest.setForceAuthentication(true);
        } else {
            log.debug("Prompt {} is not supported", prompt);
        }
        return new Pair<>(Events.Success, null);
    }

    /**
     * Check for none prompt pair.
     *
     * @param client      the client
     * @param authRequest the auth request
     * @return the pair
     */
    private Pair<Events, ? extends Object> checkForNonePrompt(final ClientDetailsEntity client,
                                                              final OIDCAuthorizationRequestContext authRequest) {
        log.debug("Prompt contains {}", ConnectRequestParameters.PROMPT_NONE);
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null) {
            log.debug("Authentication context is found for {}. Already logged in; continue without prompt",
                    auth.getPrincipal());
            return new Pair(Events.Success, auth);
        }

        log.info("Client requested no prompt");
        if (client != null && authRequest.getRedirectUri() != null) {
            try {
                final String url = redirectResolver.resolveRedirect(authRequest.getRedirectUri(), client);
                log.debug("Initial redirect url resolved for client {} is {}", client.getClientName(), url);

                final URIBuilder uriBuilder = new URIBuilder(url);
                
                if (authRequest.isImplicitResponseType()) {
                    log.debug("Request is asking for implicit grant type. Encoding parameters as fragments");
                    final StringBuilder builder = new StringBuilder();
                    builder.append(ConnectRequestParameters.ERROR)
                           .append('=')
                           .append(ConnectRequestParameters.LOGIN_REQUIRED);

                    if (!Strings.isNullOrEmpty(authRequest.getState())) {
                        builder.append(ConnectRequestParameters.STATE)
                               .append('=')
                               .append(authRequest.getState());
                    }
                    uriBuilder.setFragment(builder.toString());
                } else {
                    log.debug("Request is asking for code grant type. Encoding parameters as url parameters");
                    uriBuilder.addParameter(ConnectRequestParameters.ERROR,
                            ConnectRequestParameters.LOGIN_REQUIRED);
                    if (!Strings.isNullOrEmpty(authRequest.getState())) {
                        uriBuilder.addParameter(ConnectRequestParameters.STATE, authRequest.getState());
                    }
                }
                log.debug("Resolved redirect url {}", uriBuilder.toString());
                return new Pair<>(Events.Redirect, uriBuilder.toString());

            } catch (final URISyntaxException e) {
                log.error("Can't build redirect URI for prompt=none, sending error instead", e);
            }
        } else {
            log.warn("Access denied. Either client is not found or no redirect uri is specified");

        }
        return new Pair(Events.Failure, null);
    }
    
    /**
     * Creates a map of request parameters. Uses the first parameter value
     * in case multi-valued parameters are found
     *
     * @param parameterMap the original request parameters map
     * @return newly built parameters map
     */
    private Map<String, String> createRequestMap(final Map<String, String[]> parameterMap) {
        final Map<String, String> requestMap = new HashMap<>();
        for (final Map.Entry<String, String[]> stringEntry : parameterMap.entrySet()) {
            final String[] val = stringEntry.getValue();
            if (val != null && val.length > 0) {
                log.debug("Added request parameter {} with value {}", stringEntry.getKey(), val[0]);
                requestMap.put(stringEntry.getKey(), val[0]);
            }
        }

        return requestMap;
    }
}
