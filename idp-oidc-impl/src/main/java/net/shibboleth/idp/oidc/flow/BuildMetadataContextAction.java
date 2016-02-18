/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements. See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.oidc.OIDCException;
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
    /**
     * The Log.
     */
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
        if (rpCtx == null) {
            throw new OIDCException("Relying party context not found in the profile request");
        }
        if (rpCtx.getRelyingPartyId() == null) {
            throw new OIDCException("Relying  party id is blank");
        }
        final SAMLMetadataContext mdCtx = new SAMLMetadataContext();

        log.debug("Created client entity descriptor for {}", rpCtx.getRelyingPartyId());
        final EntityDescriptor clientEntityDescriptor = new ClientEntityDescriptor(rpCtx.getRelyingPartyId());
        mdCtx.setEntityDescriptor(clientEntityDescriptor);
        rpCtx.setRelyingPartyIdContextTree(mdCtx);

        return Events.Success.event(this);

    }
}
