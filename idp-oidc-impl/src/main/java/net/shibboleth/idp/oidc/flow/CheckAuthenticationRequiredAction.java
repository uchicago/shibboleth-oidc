/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

/**
 * Determines whether authentication is required by examining both SSO session state.
 * Returns one of the following events:
 *
 * <ul>
 *     <li>{@link Events#SessionFound sessionFound} - Authentication not required since session already exists.</li>
 *     <li>{@link Events#SessionNotFound sessionNotFound} - Authentication required since no active session exists.</li>
 * </ul>
 */
public class CheckAuthenticationRequiredAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(CheckAuthenticationRequiredAction.class);

    /**
     * Gets session bound to the idp.
     *
     * @param prc the prc
     * @return the idp session
     */
    @Nonnull
    protected IdPSession getIdPSession(final ProfileRequestContext prc) {
        final SessionContext sessionContext = prc.getSubcontext(SessionContext.class);
        if(sessionContext != null && sessionContext.getIdPSession() != null) {
            return sessionContext.getIdPSession();
        } else {
            throw new IllegalStateException("Cannot locate IdP session");
        }
    }

    @Override
    @Nonnull
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        log.debug("{} Checking whether authentication is required", getLogPrefix());
        try {
            final IdPSession e = getIdPSession(profileRequestContext);
            this.log.debug("Found session ID {}", e.getId());

            try {
                if(e.checkTimeout()) {
                    return Events.SessionFound.event(this);
                }
            } catch (final SessionException ex) {
                log.debug("Error performing session timeout check. Assuming session has expired.", ex);
            }
        } catch (final IllegalStateException ex) {
            log.debug("IdP session not found");
        }

        return Events.SessionNotFound.event(this);
    }
}
