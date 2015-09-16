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

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import com.google.gson.JsonObject;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.oidc.config.SpringSecurityAuthenticationToken;
import net.shibboleth.idp.oidc.util.OpenIdConnectUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;
import org.apache.http.client.utils.URIBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.request.ConnectRequestParameters;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.mitre.openid.connect.service.StatsService;
import org.mitre.openid.connect.service.UserInfoService;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Prepares the webflow response for the approval/consent view.
 */
public class PreAuthorizeUserApprovalAction extends AbstractProfileAction {



    private final Logger log = LoggerFactory.getLogger(PreAuthorizeUserApprovalAction.class);

    @Autowired
    private ClientDetailsEntityService clientService;

    @Autowired
    private SystemScopeService scopeService;

    @Autowired
    private ScopeClaimTranslationService scopeClaimTranslationService;

    @Autowired
    private UserInfoService userInfoService;

    @Autowired
    private StatsService statsService;

    @Autowired
    private RedirectResolver redirectResolver;

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * Instantiates a Pre-authorize user approval action.
     */
    public PreAuthorizeUserApprovalAction() {
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {

        final HttpServletRequest request = HttpServletRequestResponseContext.getRequest();
        final HttpSession session = request.getSession();
        final AuthorizationRequest authRequest = OpenIdConnectUtils.getAuthorizationRequest(request);
        if (authRequest == null || Strings.isNullOrEmpty(authRequest.getClientId())) {
            log.warn("Authorization request could not be loaded from session");
            return Events.Failure.event(this);
        }

        final String prompt = (String)authRequest.getExtensions().get(ConnectRequestParameters.PROMPT);
        final List<String> prompts = Splitter.on(ConnectRequestParameters.PROMPT_SEPARATOR)
                .splitToList(Strings.nullToEmpty(prompt));

        final ClientDetailsEntity client;

        try {
            client = clientService.loadClientByClientId(authRequest.getClientId());
            if (client == null) {
                log.error("Could not find client {}", authRequest.getClientId());
                return Events.ClientNotFound.event(this);
            }
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
            return Events.BadRequest.event(this);
        }

        if (prompts.contains("none")) {
            return handleWhenNoPromptIsPresent(springRequestContext, request, authRequest, client);
        }

        final SecurityContext securityContext = SecurityContextHolder.getContext();
        final SpringSecurityAuthenticationToken token = new SpringSecurityAuthenticationToken(profileRequestContext);
        final Authentication authentication = authenticationManager.authenticate(token);
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);

        final OpenIdConnectResponse response = buildOpenIdConnectResponse(authRequest, client);

        OpenIdConnectUtils.setResponse(springRequestContext, response);
        OpenIdConnectUtils.setAuthorizationRequest(request, authRequest,
                OpenIdConnectUtils.getAuthorizationRequestParameters(request));

        return Events.Proceed.event(this);
    }

    /**
     * Build open id connect response.
     *
     * @param authRequest the auth request
     * @param client the client
     * @return the open id connect response
     */
    private OpenIdConnectResponse buildOpenIdConnectResponse(final AuthorizationRequest authRequest,
                                                             final ClientDetailsEntity client) {
        final OpenIdConnectResponse response = new OpenIdConnectResponse();
        response.setAuthorizationRequest(authRequest);
        response.setClient(client);
        response.setRedirectUri(authRequest.getRedirectUri());

        // pre-process the scopes
        final Set<SystemScope> scopes = scopeService.fromStrings(authRequest.getScope());

        final Set<SystemScope> sortedScopes = getSystemScopes(scopes);
        response.setScopes(sortedScopes);

        final Map<String, Map<String, String>> claimsForScopes = getUserInfoClaimsForScopes(sortedScopes);
        response.setClaims(claimsForScopes);

        // client stats
        final Integer count = statsService.getCountForClientId(client.getId());
        response.setCount(count);

        if (client.getContacts() != null) {
            response.setContacts(client.getContacts());
        }

        // if the client is over a week old and has more than one registration, don't give such a big warning
        // instead, tag as "Generally Recognized As Safe" (gras)
        final Date lastWeek = new Date(System.currentTimeMillis() - (60 * 60 * 24 * 7 * 1000));
        response.setGras(count > 1 && client.getCreatedAt() != null && client.getCreatedAt().before(lastWeek));
        return response;
    }

    /**
     * Gets user info claims for scopes.
     *
     * @param sortedScopes the sorted scopes
     * @return the user info claims for scopes
     */
    private Map<String, Map<String, String>> getUserInfoClaimsForScopes(final Set<SystemScope> sortedScopes) {

        final SecurityContext securityContext = SecurityContextHolder.getContext();
        final Authentication authentication = securityContext.getAuthentication();
        final SubjectContext context = (SubjectContext) authentication.getPrincipal();

        final UserInfo user = userInfoService.getByUsername(context.getPrincipalName());
        final Map<String, Map<String, String>> claimsForScopes = new HashMap<>();
        if (user != null) {
            final JsonObject userJson = user.toJson();

            for (final SystemScope systemScope : sortedScopes) {
                final Map<String, String> claimValues = new HashMap<>();

                final Set<String> claims = scopeClaimTranslationService.getClaimsForScope(systemScope.getValue());
                claims.stream().filter(claim -> userJson.has(claim) &&
                        userJson.get(claim).isJsonPrimitive()).forEach(claim -> {
                    claimValues.put(claim, userJson.get(claim).getAsString());
                });

                claimsForScopes.put(systemScope.getValue(), claimValues);
            }
        }
        return claimsForScopes;
    }

    /**
     * Gets system scopes.
     *
     * @param scopes the scopes
     * @return the system scopes
     */
    private Set<SystemScope> getSystemScopes(final Set<SystemScope> scopes) {
        final Set<SystemScope> sortedScopes = new LinkedHashSet<>(scopes.size());
        final Set<SystemScope> systemScopes = scopeService.getAll();

        // sort scopes for display based on the inherent order of system scopes
        sortedScopes.addAll(systemScopes.stream().filter(s -> scopes.contains(s)).collect(Collectors.toList()));

        // add in any scopes that aren't system scopes to the end of the list
        sortedScopes.addAll(Sets.difference(scopes, systemScopes));
        return sortedScopes;
    }

    /**
     * Handle the case when no prompt is present.
     *
     * @param springRequestContext the spring request context
     * @param request the request
     * @param authRequest the auth request
     * @param client the client
     * @return the event
     */
    private Event handleWhenNoPromptIsPresent(@Nonnull final  RequestContext springRequestContext,
                                              @Nonnull final HttpServletRequest request,
                                              @Nonnull final AuthorizationRequest authRequest,
                                              @Nonnull final ClientDetailsEntity client) {
        try {
            final String url = redirectResolver.resolveRedirect(authRequest.getRedirectUri(), client);
            final URIBuilder uriBuilder = new URIBuilder(url);

            uriBuilder.addParameter("error", "interaction_required");
            if (!Strings.isNullOrEmpty(authRequest.getState())) {
                uriBuilder.addParameter("state", authRequest.getState());
            }

            final OpenIdConnectResponse response = new OpenIdConnectResponse();
            response.setRedirectUri(uriBuilder.toString());
            response.setAuthorizationRequest(authRequest);
            response.setClient(client);

            OpenIdConnectUtils.setResponse(springRequestContext, response);
            OpenIdConnectUtils.setAuthorizationRequest(request, authRequest,
                    OpenIdConnectUtils.getAuthorizationRequestParameters(request));
            return Events.Redirect.event(this);

        } catch (final URISyntaxException e) {
            log.error("Can't build redirect URI for prompt=none, sending error instead", e);
            return Events.BadRequest.event(this);
        }
    }

}


