package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.oidc.client.ClientEntityDescriptor;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;

public class BuildSAMLMetadataContextAction extends AbstractProfileAction {
    public BuildSAMLMetadataContextAction() {
    }

    protected Event doExecute(@Nonnull RequestContext springRequestContext,
                              @Nonnull ProfileRequestContext profileRequestContext) {
        RelyingPartyContext rpCtx = profileRequestContext.getSubcontext(RelyingPartyContext.class, false);
        if(rpCtx == null) {
            throw new IllegalArgumentException("RelyingPartyContext not found");
        } else {
            SAMLMetadataContext mdCtx = new SAMLMetadataContext();
            mdCtx.setEntityDescriptor(new ClientEntityDescriptor(rpCtx.getRelyingPartyId()));
            rpCtx.setRelyingPartyIdContextTree(mdCtx);
            return ActionSupport.buildProceedEvent(this);
        }
    }
}