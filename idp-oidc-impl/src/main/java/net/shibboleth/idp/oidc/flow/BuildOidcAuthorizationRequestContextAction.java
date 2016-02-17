package net.shibboleth.idp.oidc.flow;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import net.shibboleth.idp.oidc.util.OidcUtils;
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
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Builds an oidc authZ context message from an incoming request.
 */
public class BuildOidcAuthorizationRequestContextAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(BuildOidcAuthorizationRequestContextAction.class);

    @Autowired
    private OAuth2RequestFactory authRequestFactory;

    @Autowired
    private ClientDetailsEntityService clientService;

    @Autowired
    private RedirectResolver redirectResolver;

    /**
     * Instantiates a new authentication context action.
     */
    public BuildOidcAuthorizationRequestContextAction() {
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        final HttpServletRequest request = OidcUtils.getHttpServletRequest(springRequestContext);
        if (request == null) {
            throw new RuntimeException("HttpServletRequest cannot be null");
        }

        final HttpServletResponse response = OidcUtils.getHttpServletResponse(springRequestContext);
        if (response == null) {
            throw new RuntimeException("HttpServletRequest cannot be null");
        }

        final AuthorizationRequest authorizationRequest = createAuthorizationRequest(request);
        if (Strings.isNullOrEmpty(authorizationRequest.getClientId())) {
            throw new RuntimeException("No client id is specified in the authorization request");
        }

        final ClientDetailsEntity client = loadClientObject(authorizationRequest);
        if (!Strings.isNullOrEmpty(authorizationRequest.getRedirectUri())) {
            boolean found = false;
            final Iterator<String> it = client.getRedirectUris().iterator();

            while (!found && it.hasNext()) {
                found = it.next().equals(authorizationRequest.getRedirectUri());
            }
            if (!found) {
                throw new InvalidClientException("Redirect uri in the authorization request " +
                        authorizationRequest.getRedirectUri() + " is not registered for client " + client.getClientId());
            }
        }
        log.debug("Found client {}.", client.getClientId());

        processLoginHintParameterIfNeeded(request, authorizationRequest);

        Pair<Events, ? extends Object> pairEvent = new Pair<>(Events.Success, null);
        final String prompt = (String) authorizationRequest.getExtensions().get(ConnectRequestParameters.PROMPT);
        if (prompt != null) {
            log.debug("Authorization request contains prompt {}", prompt);
            pairEvent = checkForPrompts(prompt, request, client, authorizationRequest);
        } else if (authorizationRequest.getExtensions().get(ConnectRequestParameters.MAX_AGE) != null ||
                client.getDefaultMaxAge() != null) {
            log.debug("Authorization request or client configuration contains max age");
            checkForMaxAge(request, client, authorizationRequest);
        }

        return produceFinalEvent(profileRequestContext, response, authorizationRequest, pairEvent);
    }

    private Event produceFinalEvent(final ProfileRequestContext profileRequestContext, final HttpServletResponse response,
                                    final AuthorizationRequest authorizationRequest,
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
                        throw new IllegalStateException("No redirect url could be found based on the request");
                    }
                case Success:
                    log.debug("Proceeding with building the authorization context based on the request");
                    final OidcAuthorizationRequestContext authZContext = new OidcAuthorizationRequestContext();
                    authZContext.setAuthorizationRequest(authorizationRequest);
                    profileRequestContext.addSubcontext(authZContext, true);
                    break;
            }
            final Event ev = pairEvent.getFirst().event(this);
            log.debug("Returning final event {}", ev.getId());
            return ev;
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private ClientDetailsEntity loadClientObject(final AuthorizationRequest authorizationRequest) {
        log.debug("Loading client by id {}", authorizationRequest.getClientId());
        return clientService.loadClientByClientId(authorizationRequest.getClientId());
    }

    private void processLoginHintParameterIfNeeded(final HttpServletRequest request, final AuthorizationRequest authorizationRequest) {
        final Object loginHint = authorizationRequest.getExtensions().get(ConnectRequestParameters.LOGIN_HINT);
        if (loginHint != null) {
            OidcUtils.setRequestParameter(request, ConnectRequestParameters.LOGIN_HINT, loginHint);
            log.debug("Saved login hint {} into session", loginHint);
        } else {
            OidcUtils.removeSessionAttribute(request, ConnectRequestParameters.LOGIN_HINT);
            log.debug("Removed login hint attribute from session");
        }
    }

    private AuthorizationRequest createAuthorizationRequest(final HttpServletRequest request) {
        log.debug("Constructing authorization request");
        final Map<String, String> requestParameters = createRequestMap(request.getParameterMap());
        return authRequestFactory.createAuthorizationRequest(requestParameters);
    }

    /**
     * Check for max age. Determines max-age either from client configuration
     * or from the authorization request. Tries to figure out if an existing
     * authentication session bound to spring security is too old, and if so,
     * it will clear it out.
     *
     * @param request the request
     */
    private void checkForMaxAge(final HttpServletRequest request, final ClientDetailsEntity client,
                                final AuthorizationRequest authRequest) {

        Integer max = client != null ? client.getDefaultMaxAge() : null;
        log.debug("Client configuration set to max age {}", max);

        final String maxAge = (String) authRequest.getExtensions().get(ConnectRequestParameters.MAX_AGE);
        log.debug("Authorization request contains max age {}", maxAge);
        if (maxAge != null) {
            max = Integer.parseInt(maxAge);
        }

        if (max != null) {
            log.debug("Evaluated max age to use as {}", max);
            final Date authTime = OidcUtils.getAuthenticationTimestamp(request);
            log.debug("Authentication time set to {}", authTime);
            final Date now = new Date();
            if (authTime != null) {
                final long seconds = (now.getTime() - authTime.getTime()) / 1000;
                if (seconds > max) {
                    log.debug("Authentication is too old: {}. Clearing authentication context", authTime);
                    SecurityContextHolder.getContext().setAuthentication(null);
                }
            }
        }
    }

    /**
     * Check for prompts in the authorization request. Evaluates
     * if redirects to the client should execute
     * or authentication cleared forcing the user
     * to authenticate again.
     *
     * @param prompt  the prompt
     * @param request the request
     * @return the event
     * @throws IOException the IO exception
     */
    private Pair<Events, ? extends Object> checkForPrompts(final String prompt,
                                                           final HttpServletRequest request,
                                                           final ClientDetailsEntity client,
                                                           final AuthorizationRequest authRequest) {

        final List<String> prompts = Splitter.on(ConnectRequestParameters.PROMPT_SEPARATOR)
                .splitToList(Strings.nullToEmpty(prompt));
        if (prompts.contains(ConnectRequestParameters.PROMPT_NONE)) {
            return checkForNonePrompt(client, authRequest);
        }

        if (prompts.contains(ConnectRequestParameters.PROMPT_LOGIN)) {
            checkForLoginPrompt(request);
        }

        log.debug("Prompt {} is not supported", prompt);
        return new Pair<>(Events.Success, null);
    }

    private Pair<Events, ? extends Object> checkForNonePrompt(final ClientDetailsEntity client, final AuthorizationRequest authRequest) {
        log.debug("Prompt contains {}", ConnectRequestParameters.PROMPT_NONE);
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null) {
            log.debug("Authentication context is found for {}. Already logged in; continue without prompt", auth.getPrincipal());
            return new Pair(Events.Success, auth);
        }

        log.info("Client requested no prompt");
        if (client != null && authRequest.getRedirectUri() != null) {
            try {
                final String url = redirectResolver.resolveRedirect(authRequest.getRedirectUri(), client);
                log.debug("Initial redirect url resolved for client {} is {}", client.getClientName(), url);

                final URIBuilder uriBuilder = new URIBuilder(url);
                uriBuilder.addParameter(ConnectRequestParameters.ERROR,
                        ConnectRequestParameters.LOGIN_REQUIRED);
                if (!Strings.isNullOrEmpty(authRequest.getState())) {
                    uriBuilder.addParameter(ConnectRequestParameters.STATE, authRequest.getState());
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

    private void checkForLoginPrompt(final HttpServletRequest request) {
        log.debug("Prompt contains {}", ConnectRequestParameters.PROMPT_LOGIN);

        if (OidcUtils.isRequestPrompted(request)) {
            OidcUtils.setPromptRequested(request);
            final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                SecurityContextHolder.getContext().setAuthentication(null);
                log.debug("Cleared authentication {} from context. Proceeding with filter chain", auth.getName());
            } else {
                log.debug("Authentication is not found in the context. Proceeding with filter chain");
            }
        } else {
            OidcUtils.removeRequestPrompted(request);
        }
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
