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
package net.shibboleth.idp.oidc.config;

import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.request.ConnectOAuth2RequestFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.util.Map;

/**
 * The type Shibboleth o auth 2 request factory.
 */
@Service("shibbolethOAuth2RequestFactory")
@Primary
public class ShibbolethOAuth2RequestFactory extends ConnectOAuth2RequestFactory {
    /**
     * The Log.
     */
    private final Logger log = LoggerFactory.getLogger(ShibbolethOAuth2RequestFactory.class);

    /**
     * Instantiates a new Shibboleth o auth 2 request factory.
     *
     * @param clientDetailsService the client details service
     */
    @Autowired
    public ShibbolethOAuth2RequestFactory(final ClientDetailsEntityService clientDetailsService) {
        super(clientDetailsService);
    }

    @Override
    public AuthorizationRequest createAuthorizationRequest(final Map<String, String> inputParams) {
        final AuthorizationRequest request = super.createAuthorizationRequest(inputParams);
        if (inputParams.containsKey(OIDCConstants.ACR_VALUES)) {
            try {
                log.debug("Authorization request contains {}. Decoding and storing values into the request", 
                        OIDCConstants.ACR_VALUES);
                request.getExtensions().put(OIDCConstants.ACR_VALUES,
                        URLDecoder.decode(inputParams.get(OIDCConstants.ACR_VALUES), "UTF-8"));
            } catch (final Exception e) {
                log.warn("Unable to decode acr_values in the authorization request", e);
            }
        }
        return request;
    }
}
