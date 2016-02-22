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

import com.google.common.base.MoreObjects;
import net.shibboleth.idp.oidc.config.OIDCConstants;
import org.mitre.openid.connect.request.ConnectRequestParameters;
import org.opensaml.messaging.context.BaseContext;
import org.springframework.security.oauth2.provider.AuthorizationRequest;

import javax.annotation.Nonnull;

/**
 * The type Oidc authorization request context.
 */
public class OIDCAuthorizationRequestContext extends BaseContext {

    /**
     * The Force authentication.
     */
    private boolean forceAuthentication;

    /**
     * The Authorization request.
     */
    @Nonnull
    private AuthorizationRequest authorizationRequest;

    /**
     * Gets authorization request.
     *
     * @return the authorization request
     */
    public AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    /**
     * Sets authorization request.
     *
     * @param req the req
     */
    public void setAuthorizationRequest(final AuthorizationRequest req) {
        this.authorizationRequest = req;
    }

    /**
     * Gets client id.
     *
     * @return the client id
     */
    public String getClientId() {
        return this.authorizationRequest.getClientId();
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("authorizationRequestClientId", authorizationRequest.getClientId())
                .add("authorizationRequestRedirectUri", authorizationRequest.getRedirectUri())
                .add("authorizationRequestRequestParameters", authorizationRequest.getRequestParameters())
                .add("authorizationRequestExtensions", authorizationRequest.getExtensions().values())
                .add("authorizationRequestScope", authorizationRequest.getScope())
                .add("authorizationRequestState", authorizationRequest.getState())
                .add("authorizationRequestResponseTypes", authorizationRequest.getResponseTypes())
                .toString();
    }

    /**
     * Gets login hint.
     *
     * @return the login hint
     */
    public Object getLoginHint() {
        return authorizationRequest.getExtensions().get(ConnectRequestParameters.LOGIN_HINT);
    }

    /**
     * Gets nonce.
     *
     * @return the nonce
     */
    public String getNonce() {
        return (String) authorizationRequest.getExtensions().get(ConnectRequestParameters.NONCE);
    }


    /**
     * Gets max age.
     *
     * @return the max age
     */
    public String getMaxAge() {
        return (String) authorizationRequest.getExtensions().get(ConnectRequestParameters.MAX_AGE);
    }

    /**
     * Gets redirect uri.
     *
     * @return the redirect uri
     */
    public String getRedirectUri() {
        return this.authorizationRequest.getRedirectUri();
    }

    /**
     * Gets state.
     *
     * @return the state
     */
    public String getState() {
        return this.authorizationRequest.getState();
    }

    /**
     * Is force authentication boolean.
     *
     * @return the boolean
     */
    public boolean isForceAuthentication() {
        return forceAuthentication;
    }

    /**
     * Sets force authentication.
     *
     * @param force the force
     */
    public void setForceAuthentication(final boolean force) {
        this.forceAuthentication = force;
    }


    /**
     * Is implicit response type boolean.
     *
     * @return the boolean
     */
    public boolean isImplicitResponseType() {
        return authorizationRequest.getResponseTypes().contains(OIDCConstants.TOKEN);
    }
}
