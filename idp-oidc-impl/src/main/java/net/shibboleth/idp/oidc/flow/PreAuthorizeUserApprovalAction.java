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

import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.oidc.OIDCException;
import net.shibboleth.idp.oidc.client.userinfo.ShibbolethUserInfoService;
import net.shibboleth.idp.oidc.client.userinfo.authn.SpringSecurityAuthenticationToken;
import net.shibboleth.idp.oidc.client.userinfo.authn.SpringSecurityAuthenticationTokenFactory;
import net.shibboleth.idp.oidc.config.OIDCConstants;
import net.shibboleth.idp.oidc.util.OIDCUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.model.ClientStat;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.mitre.openid.connect.service.StatsService;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Prepares the webflow response for the approval/consent view.
 */
public class PreAuthorizeUserApprovalAction extends AbstractProfileAction {
    /**
     * The Log.
     */
    private final Logger log = LoggerFactory.getLogger(PreAuthorizeUserApprovalAction.class);

    /**
     * The Client service.
     */
    @Autowired
    private ClientDetailsEntityService clientService;

    /**
     * The Scope service.
     */
    @Autowired
    private SystemScopeService scopeService;

    /**
     * The Scope claim translation service.
     */
    @Autowired
    private ScopeClaimTranslationService scopeClaimTranslationService;

    /**
     * The User info service.
     */
    @Autowired
    @Qualifier("openIdConnectUserInfoService")
    private ShibbolethUserInfoService userInfoService;

    /**
     * The Stats service.
     */
    @Autowired
    private StatsService statsService;

    /**
     * The Redirect resolver.
     */
    @Autowired
    private RedirectResolver redirectResolver;

    /**
     * Instantiates a Pre-authorize user approval action.
     */
    public PreAuthorizeUserApprovalAction() {
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {

        this.userInfoService.initialize(profileRequestContext);

        final OIDCAuthorizationRequestContext authZContext =
                profileRequestContext.getSubcontext(OIDCAuthorizationRequestContext.class);
        if (authZContext == null) {
            log.warn("No authorization request could be located in the profile request context");
            return Events.Failure.event(this);
        }

        final AuthorizationRequest authRequest = authZContext.getAuthorizationRequest();
        if (authRequest == null || Strings.isNullOrEmpty(authRequest.getClientId())) {
            log.warn("Authorization request could not be loaded from session");
            return Events.Failure.event(this);
        }

        /*
        final String prompt = (String)authRequest.getExtensions().get(ConnectRequestParameters.PROMPT);
        final List<String> prompts = Splitter.on(ConnectRequestParameters.PROMPT_SEPARATOR)
                .splitToList(Strings.nullToEmpty(prompt));
        */

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

        /*
        if (prompts.contains(ConnectRequestParameters.PROMPT_NONE)) {
            log.debug("Handling authorization when prompt contains none");
            return handleWhenNoPromptIsPresent(springRequestContext, request, authRequest, client);
        }
        */

        final Authentication authentication =
                SpringSecurityAuthenticationTokenFactory.buildAuthentication(profileRequestContext);
        storeSpringSecurityAuthenticationContext(profileRequestContext, springRequestContext, authentication);
        storeAuthenticationTimeIntoAuthorizationRequest(authentication, authRequest);
        final OIDCResponse response = buildOpenIdConnectResponse(authRequest, client);
        final OIDCAuthorizationResponseContext responseContext = new OIDCAuthorizationResponseContext();
        responseContext.setOidcResponse(response);
        profileRequestContext.addSubcontext(responseContext);
        return Events.Proceed.event(this);
    }

    /**
     * Store authentication time into authorization request.
     *
     * @param authentication the authentication
     * @param authRequest    the auth request
     */
    private static void storeAuthenticationTimeIntoAuthorizationRequest(final Authentication authentication,
                                                                 final AuthorizationRequest authRequest) {
        authRequest.getExtensions().put(OIDCConstants.AUTH_TIME,
                ((SpringSecurityAuthenticationToken) authentication).getAuthenticationDateTime().getMillis());
    }

    /**
     * Store spring security authentication context.
     *
     * @param profileRequestContext the profile request context
     * @param springRequestContext  the spring request context
     * @param authentication        the authentication
     */
    private void storeSpringSecurityAuthenticationContext(@Nonnull final ProfileRequestContext profileRequestContext,
                                                          final RequestContext springRequestContext, 
                                                          final Authentication authentication) {
        final HttpServletRequest request = OIDCUtils.getHttpServletRequest(springRequestContext);
        if (request == null) {
            throw new OIDCException("HttpServletRequest cannot be null");
        }

        final SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
        final HttpSession session = request.getSession();
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        log.debug("Stored authentication [{}] into Spring security context", 
                SecurityContextHolder.getContext().getAuthentication());
    }

    /**
     * Build open id connect response.
     *
     * @param authRequest the auth request
     * @param client      the client
     * @return the open id connect response
     */
    private OIDCResponse buildOpenIdConnectResponse(final AuthorizationRequest authRequest,
                                                    final ClientDetailsEntity client) {
        final OIDCResponse response = new OIDCResponse();
        response.setAuthorizationRequest(authRequest);
        response.setClient(client);
        response.setRedirectUri(authRequest.getRedirectUri());

        log.debug("Built initial response for client {} and redirect uri {}",
                client, authRequest.getRedirectUri());

        // pre-process the scopes
        final Set<SystemScope> scopes = scopeService.fromStrings(authRequest.getScope());
        log.debug("System scopes retrieved based on the authorization request scope {} are {}",
                authRequest.getScope(), scopes);

        final Set<SystemScope> sortedScopes = getSystemScopes(scopes);
        response.setScopes(sortedScopes);
        log.debug("Response will contain the following scopes {}", sortedScopes);

        final Map<String, Map<String, String>> claimsForScopes = getUserInfoClaimsForScopes(sortedScopes);
        response.setClaims(claimsForScopes);
        log.debug("Response will contain the following claims for scopes {}", claimsForScopes.keySet());

        // client stats
        final Integer count = statsService.getCountForClientId(client.getClientId()).getApprovedSiteCount();
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
        log.debug("Located UserInfo object from principal name {}", context.getPrincipalName());

        final Map<String, Map<String, String>> claimsForScopes = new HashMap<>();
        if (user != null) {
            final JsonObject userJson = user.toJson();
            log.debug("UserInfo translated to JSON is:\n{}", userJson);

            for (final SystemScope systemScope : sortedScopes) {
                final Map<String, String> claimValues = new HashMap<>();

                final Set<String> claims = scopeClaimTranslationService.getClaimsForScope(systemScope.getValue());
                log.debug("Processing system scope {} for the following claims: {}", systemScope.getValue(), claims);
                for (final String claim : claims) {
                    final JsonElement element = userJson.get(claim);
                    if (userJson.has(claim) && element.isJsonPrimitive()) {
                        claimValues.put(claim, element.getAsString());
                        log.debug("Added claim {} with value {}", claim, element.getAsString());
                    }
                }
                log.debug("Final claims for system scope {} are {}", systemScope.getValue(), claimValues);
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
        for (final SystemScope systemScope : systemScopes) {
            if (scopes.contains(systemScope)) {
                sortedScopes.add(systemScope);
            }
        }
        // add in any scopes that aren't system scopes to the end of the list
        sortedScopes.addAll(Sets.difference(scopes, systemScopes));
        return sortedScopes;
    }


    /**
     * Handle the case when no prompt is present.
     *
     * @param springRequestContext the spring request context
     * @param request              the request
     * @param authRequest          the auth request
     * @param client               the client
     * @return the event
     */

    /*
    private Event handleWhenNoPromptIsPresent(@Nonnull final RequestContext springRequestContext,
                                              @Nonnull final HttpServletRequest request,
                                              @Nonnull final ProfileRequestContext profileRequestContext,
                                              @Nonnull final AuthorizationRequest authRequest,
                                              @Nonnull final ClientDetailsEntity client) {
        try {
            final String url = redirectResolver.resolveRedirect(authRequest.getRedirectUri(), client);
            log.debug("Initial redirect url resolved for client {} is {}", client.getClientName(), url);

            final URIBuilder uriBuilder = new URIBuilder(url);

            uriBuilder.addParameter("error", "interaction_required");
            if (!Strings.isNullOrEmpty(authRequest.getState())) {
                uriBuilder.addParameter("state", authRequest.getState());
                log.debug("Added state value {}", authRequest.getState());
            }

            final OIDCResponse response = new OIDCResponse();

            log.debug("Resolved redirect url {}", uriBuilder.toString());
            response.setRedirectUri(uriBuilder.toString());
            response.setAuthorizationRequest(authRequest);
            response.setClient(client);
            log.debug("Built initial response for client {} and redirect uri {}", client, authRequest.getRedirectUri());

            final OIDCAuthorizationResponseContext responseContext = new OIDCAuthorizationResponseContext();
            responseContext.setOidcResponse(response);
            profileRequestContext.addSubcontext(responseContext);

            return Events.Redirect.event(this);

        } catch (final URISyntaxException e) {
            log.error("Can't build redirect URI for prompt=none, sending error instead", e);
            return Events.BadRequest.event(this);
        }
    }
    */

}


