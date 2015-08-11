package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.session.IdPSession;
import net.shibboleth.idp.session.SessionException;
import net.shibboleth.idp.session.context.SessionContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;

public class CheckAuthenticationRequiredAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(CheckAuthenticationRequiredAction.class);

    public CheckAuthenticationRequiredAction() {
    }

    @Nonnull
    protected IdPSession getIdPSession(ProfileRequestContext prc) {
        SessionContext sessionContext = (SessionContext) prc.getSubcontext(SessionContext.class);
        if(sessionContext != null && sessionContext.getIdPSession() != null) {
            return sessionContext.getIdPSession();
        } else {
            throw new IllegalStateException("Cannot locate IdP session");
        }
    }

    @Nonnull
    protected Event doExecute(@Nonnull RequestContext springRequestContext, @Nonnull ProfileRequestContext profileRequestContext) {
        log.debug("{} Checking whether authentication is required", getLogPrefix());
        try {
            IdPSession e = this.getIdPSession(profileRequestContext);
            this.log.debug("Found session ID {}", e.getId());

            try {
                if(e.checkTimeout()) {
                    return Events.SessionFound.event(this);
                }
            } catch (SessionException ex) {
                log.debug("Error performing session timeout check. Assuming session has expired.", ex);
            }
        } catch (IllegalStateException ex) {
            log.debug("IdP session not found");
        }

        return Events.SessionNotFound.event(this);
    }
}
