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
package net.shibboleth.idp.oidc.endpoints;

import net.shibboleth.idp.oidc.util.OIDCUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * The discovery endpoint.
 */
@Controller("oidcWellknownEndpoint")
@RequestMapping('/' + org.mitre.discovery.web.DiscoveryEndpoint.WELL_KNOWN_URL)
public final class WellKnownEndpoint extends org.mitre.discovery.web.DiscoveryEndpoint {
    /**
     * URL endpoint.
     */
    public static final String URL = '/' + WELL_KNOWN_URL;

    /**
     * Default endpoint string.
     *
     * @param model the model
     * @return the string
     */
    @RequestMapping(method= RequestMethod.GET)
    public String defaultEndpoint(final Model model) {
        final String view = super.providerConfiguration(model);
        model.mergeAttributes(OIDCUtils.buildOidcServerConfigurationModelForDiscovery(model));
        return view;
    }
}


