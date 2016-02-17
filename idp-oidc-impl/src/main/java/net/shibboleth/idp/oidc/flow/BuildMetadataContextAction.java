package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.oidc.client.metadata.ClientEntityDescriptor;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;

/**
 * Builds a {@link SAMLMetadataContext} child of {@link RelyingPartyContext}
 * to facilitate relying party selection by group name.
 */
public class BuildMetadataContextAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(BuildAuthenticationContextAction.class);

    /**
     * Instantiates a new SAML metadata context action.
     */
    public BuildMetadataContextAction() {
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        final RelyingPartyContext rpCtx = profileRequestContext.getSubcontext(RelyingPartyContext.class, false);
        if (rpCtx == null || rpCtx.getRelyingPartyId() == null) {
            throw new IllegalArgumentException("RelyingPartyContext not found in the profile request, or relying party id is blank");
        }
        final SAMLMetadataContext mdCtx = new SAMLMetadataContext();

        log.debug("Created client entity descriptor for {}", rpCtx.getRelyingPartyId());
        final EntityDescriptor clientEntityDescriptor = new ClientEntityDescriptor(rpCtx.getRelyingPartyId());
        mdCtx.setEntityDescriptor(clientEntityDescriptor);
        rpCtx.setRelyingPartyIdContextTree(mdCtx);

        return Events.Success.event(this);

    }
}
