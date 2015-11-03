package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.core.collection.ParameterMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;

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

        final ParameterMap params = springRequestContext.getRequestParameters();

        return ActionSupport.buildProceedEvent(this);
    }
}
