package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.oidc.util.OIDCUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Initializes the OIDC protocol interaction at the <code>/login</code> URI.
 */
public class InitializeLoginAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(InitializeLoginAction.class);

    /**
     * Instantiates a new login action.
     */
    public InitializeLoginAction() {
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        log.debug("{} Initializing login action", getLogPrefix());
        final HttpServletRequest request = OIDCUtils.getHttpServletRequest(springRequestContext);
        if (request == null) {
            throw new RuntimeException("HttpServletRequest cannot be null");
        }

        final HttpServletResponse response = OIDCUtils.getHttpServletResponse(springRequestContext);
        if (response == null) {
            throw new RuntimeException("HttpServletRequest cannot be null");
        }
        HttpServletRequestResponseContext.loadCurrent(request, response);
        return Events.Success.event(this);
    }
}
