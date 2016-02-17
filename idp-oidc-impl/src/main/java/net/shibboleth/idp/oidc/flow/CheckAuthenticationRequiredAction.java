package net.shibboleth.idp.oidc.flow;

import com.google.common.base.Function;
import net.shibboleth.idp.oidc.config.OIDCConstants;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.session.IdPSession;
import net.shibboleth.idp.session.SessionException;
import net.shibboleth.idp.session.context.SessionContext;
import org.joda.time.DateTime;
import org.joda.time.Days;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import java.util.Date;

/**
 * Determines whether authentication is required by examining both SSO session state.
 * Returns one of the following events:
 * <p/>
 * <ul>
 * <li>{@link Events#SessionFound sessionFound} - Authentication not required since session already exists.</li>
 * <li>{@link Events#SessionNotFound sessionNotFound} - Authentication required since no active session exists.</li>
 * </ul>
 */
public class CheckAuthenticationRequiredAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(CheckAuthenticationRequiredAction.class);

    private final Function<ProfileRequestContext, SessionContext> sessionContextFunction =
            new ChildContextLookup(SessionContext.class, false);

    @Autowired
    private ClientDetailsEntityService clientService;

    /**
     * Gets session bound to the idp.
     *
     * @param prc the prc
     * @return the idp session
     */
    @Nonnull
    protected IdPSession getIdPSession(final ProfileRequestContext prc) {
        final SessionContext sessionContext = sessionContextFunction.apply(prc);
        if (sessionContext != null && sessionContext.getIdPSession() != null) {
            return sessionContext.getIdPSession();
        }
        throw new IllegalStateException("Cannot locate IdP session");
    }

    @Override
    @Nonnull
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        log.debug("{} Checking whether authentication is required", getLogPrefix());
        try {
            final IdPSession idpSession = getIdPSession(profileRequestContext);
            this.log.debug("Found IdP session ID {}", idpSession.getId());

            try {
                log.debug("Checking for session timeouts with creation instant {} and last activity instant {}",
                        idpSession.getCreationInstant(), idpSession.getLastActivityInstant());

                if (idpSession.checkTimeout()) {
                    log.debug("IdP session ID {} is still valid. Checking for {}", idpSession.getId(), OIDCConstants.MAX_AGE);

                    final OIDCAuthorizationRequestContext authZContext =
                            profileRequestContext.getSubcontext(OIDCAuthorizationRequestContext.class);
                    if (authZContext == null) {
                        log.warn("No authorization request could be located in the profile request context");
                        return Events.Failure.event(this);
                    }

                    final ClientDetailsEntity client = clientService.loadClientByClientId(
                            authZContext.getAuthorizationRequest().getClientId());
                    if (client == null) {
                        log.warn("No client could be located based on the authorization request");
                        return Events.Failure.event(this);
                    }

                    if (authZContext.getMaxAge() != null || client.getDefaultMaxAge() != null) {
                        log.debug("Authorization request or client configuration contains {}", OIDCConstants.MAX_AGE);
                        if (isAuthenticationTooOldForRequiredMaxAge(client, authZContext, idpSession)) {
                            log.debug("Forcing the IdP to ignore the existing session");

                            authZContext.setForceAuthentication(true);
                            return Events.SessionNotFound.event(this);
                        }
                    }
                    return Events.SessionFound.event(this);
                }
            } catch (final SessionException ex) {
                log.debug("Error performing session timeout check. Assuming session has expired.", ex);
            }
        } catch (final IllegalStateException ex) {
            log.debug("IdP session not found");
        }

        return Events.SessionNotFound.event(this);
    }

    /**
     * Check for max age. Determines max-age either from client configuration
     * or from the authorization request. Tries to figure out if an existing
     * authentication session bound to spring security is too old, and if so,
     * it will clear it out.
     *
     * @param client      the client
     * @param authRequest the auth request
     * @param idpSession
     */
    private boolean isAuthenticationTooOldForRequiredMaxAge(final ClientDetailsEntity client,
                                                            final OIDCAuthorizationRequestContext authRequest, final IdPSession idpSession) {

        Integer max = client != null ? client.getDefaultMaxAge() : null;
        log.debug("Client configuration set to max age {}", max);

        final String maxAge = authRequest.getMaxAge();
        log.debug("Authorization request contains max age {}", maxAge);
        if (maxAge != null) {
            max = Integer.parseInt(maxAge);
            log.debug("Evaluated max age to use as {}", max);
            final DateTime authTime = new DateTime(idpSession.getCreationInstant());
            log.debug("Idp Session creation instant set to {}", authTime);

            final DateTime now = DateTime.now();
            log.debug("Now instant {}", now);

            final long diffInSeconds = (now.getMillis() - authTime.getMillis()) / 1000;
            log.debug("Difference between now and authentication instant in seconds is {}", diffInSeconds);
            if (diffInSeconds > max) {
                log.debug("Authentication is too old: {}. Clearing authentication context", authTime);
                return true;
            }
        }

        return false;
    }
}
