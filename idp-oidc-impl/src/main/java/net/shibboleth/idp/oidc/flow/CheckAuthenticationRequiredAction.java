package net.shibboleth.idp.oidc.flow;

import com.google.common.base.Function;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.session.IdPSession;
import net.shibboleth.idp.session.SessionException;
import net.shibboleth.idp.session.context.SessionContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;

/**
 * Determines whether authentication is required by examining both SSO session state.
 * Returns one of the following events:
 *
 * <ul>
 *     <li>{@link Events#SessionFound sessionFound} - Authentication not required since session already exists.</li>
 *     <li>{@link Events#SessionNotFound sessionNotFound} - Authentication required since no active session exists.</li>
 * </ul>
 */
public class CheckAuthenticationRequiredAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(CheckAuthenticationRequiredAction.class);

    private final Function<ProfileRequestContext, SessionContext> sessionContextFunction =
            new ChildContextLookup(SessionContext.class, false);

    /**
     * Gets session bound to the idp.
     *
     * @param prc the prc
     * @return the idp session
     */
    @Nonnull
    protected IdPSession getIdPSession(final ProfileRequestContext prc) {
        final SessionContext sessionContext = sessionContextFunction.apply(prc);
        if(sessionContext != null && sessionContext.getIdPSession() != null) {
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
            final IdPSession e = getIdPSession(profileRequestContext);
            this.log.debug("Found session ID {}", e.getId());

            try {
                if(e.checkTimeout()) {
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
}
