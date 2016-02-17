package net.shibboleth.idp.oidc.flow;


import com.google.common.base.Strings;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;

/**
 * Creates the {@link RelyingPartyContext} as a child of the {@link ProfileRequestContext}.
 */
public class BuildRelyingPartyContextAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(BuildRelyingPartyContextAction.class);

    private ProfileConfiguration profileConfiguration;

    @Autowired
    private ClientDetailsEntityService clientService;

    public void setProfileConfiguration(final ProfileConfiguration profileConfiguration) {
        this.profileConfiguration = profileConfiguration;
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {

        final OIDCAuthorizationRequestContext authZContext = profileRequestContext.getSubcontext(OIDCAuthorizationRequestContext.class);
        if (authZContext == null) {
            log.warn("No authorization request could be located in the profile request context");
            return Events.Failure.event(this);
        }

        final AuthorizationRequest authRequest = authZContext.getAuthorizationRequest();
        if (authRequest == null || Strings.isNullOrEmpty(authRequest.getClientId())) {
            log.warn("Authorization request could not be loaded from session");
            return Events.Failure.event(this);
        }

        final ClientDetailsEntity client = this.clientService.loadClientByClientId(authRequest.getClientId());

        if (client == null) {
            log.warn("Client configuration could not be loaded from session");
            return Events.Failure.event(this);
        }
        final RelyingPartyContext rpc = new RelyingPartyContext();

        rpc.setVerified(true);
        rpc.setRelyingPartyId(client.getClientId());
        log.debug("{} Setting up RP context for verified relying party {}",
                getLogPrefix(), client.getClientId());
        profileRequestContext.addSubcontext(rpc);
        return Events.Success.event(this);
    }
}
