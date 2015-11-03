package net.shibboleth.idp.oidc.flow;


import com.google.common.base.Strings;
import net.shibboleth.idp.oidc.util.OpenIdConnectUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

/**
 * Creates the {@link RelyingPartyContext} as a child of the {@link ProfileRequestContext}.
 */
public class BuildRelyingPartyContextAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(BuildRelyingPartyContextAction.class);


    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {


        final HttpServletRequest request = HttpServletRequestResponseContext.getRequest();
        final AuthorizationRequest authRequest = OpenIdConnectUtils.getAuthorizationRequest(request);
        if (authRequest == null || Strings.isNullOrEmpty(authRequest.getClientId())) {
            log.warn("Authorization request could not be loaded from session");
            return Events.Failure.event(this);
        }

        final ClientDetailsEntity client = OpenIdConnectUtils.getClient(request);

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
        return ActionSupport.buildProceedEvent(this);
    }
}
