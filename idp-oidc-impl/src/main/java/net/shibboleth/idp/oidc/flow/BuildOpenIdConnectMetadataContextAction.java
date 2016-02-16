package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.oidc.client.metadata.ClientEntityDescriptor;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;

/**
 * Builds a {@link SAMLMetadataContext} child of {@link RelyingPartyContext}
 * to facilitate relying party selection by group name.
 */
public class BuildOpenIdConnectMetadataContextAction extends AbstractProfileAction {
    /**
     * Instantiates a new SAML metadata context action.
     */
    public BuildOpenIdConnectMetadataContextAction() {
    }

    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        final RelyingPartyContext rpCtx = profileRequestContext.getSubcontext(RelyingPartyContext.class, false);
        if (rpCtx == null) {
            throw new IllegalArgumentException("RelyingPartyContext not found");
        }
        final SAMLMetadataContext mdCtx = new SAMLMetadataContext();
        final EntityDescriptor clientEntityDescriptor = new ClientEntityDescriptor(rpCtx.getRelyingPartyId());
        mdCtx.setEntityDescriptor(clientEntityDescriptor);
        rpCtx.setRelyingPartyIdContextTree(mdCtx);


        return ActionSupport.buildProceedEvent(this);

    }
}
