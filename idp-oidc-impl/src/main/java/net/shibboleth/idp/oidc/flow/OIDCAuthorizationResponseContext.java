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

import org.opensaml.messaging.context.BaseContext;

/**
 * The type Oidc authorization response context.
 */
public class OIDCAuthorizationResponseContext extends BaseContext {

    /**
     * The Oidc response.
     */
    private OIDCResponse oidcResponse;

    /**
     * Gets oidc response.
     *
     * @return the oidc response
     */
    public OIDCResponse getOidcResponse() {
        return oidcResponse;
    }

    /**
     * Sets oidc response.
     *
     * @param res the res
     */
    public void setOidcResponse(final OIDCResponse res) {
        this.oidcResponse = res;
    }

}
