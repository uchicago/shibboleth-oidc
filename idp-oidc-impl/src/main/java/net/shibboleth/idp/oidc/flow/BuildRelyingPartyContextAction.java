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
    /**
     * The Log.
     */
    private final Logger log = LoggerFactory.getLogger(BuildRelyingPartyContextAction.class);

    /**
     * The Profile configuration.
     */
    private ProfileConfiguration profileConfiguration;

    /**
     * The Client service.
     */
    @Autowired
    private ClientDetailsEntityService clientService;

    /**
     * Sets profile configuration.
     *
     * @param config the config
     */
    public void setProfileConfiguration(final ProfileConfiguration config) {
        this.profileConfiguration = config;
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {

        final OIDCAuthorizationRequestContext authZContext = 
                profileRequestContext.getSubcontext(OIDCAuthorizationRequestContext.class);
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
