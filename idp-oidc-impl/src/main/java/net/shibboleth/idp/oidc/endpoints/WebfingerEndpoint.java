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

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * This is {@link WebfingerEndpoint}.
 */
@Controller("oidcWebfingerEndpoint")
@RequestMapping("/webfinger" )
public class WebfingerEndpoint extends org.mitre.discovery.web.DiscoveryEndpoint {
    /**
     * The constant URL.
     */
    public static final String URL = "/webfinger";

    @RequestMapping(
            method = RequestMethod.GET,
            params = {"resource", "rel=http://openid.net/specs/connect/1.0/issuer"},
            produces = {"application/json"}
    )
    @Override
    public String webfinger(@RequestParam("resource") final String resource, @RequestParam(value = "rel", required = false) final String rel, final Model model) {
        return super.webfinger(resource, rel, model);
    }
}
