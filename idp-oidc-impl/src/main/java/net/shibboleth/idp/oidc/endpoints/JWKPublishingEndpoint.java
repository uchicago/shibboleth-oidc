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

import com.nimbusds.jose.jwk.JWK;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.openid.connect.view.JWKSetView;
import org.mitre.openid.connect.web.JWKSetPublishingEndpoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

/**
 * A JWK endpoint that remaps the controller.
 */
@Controller("jwkPublishingEndpoint")
public class JWKPublishingEndpoint extends JWKSetPublishingEndpoint {

    /**
     * URL endpoint for JWK used to map requests.
     */
    public static final String URL = "/oidc/jwk";

    /**
     * The Jwt service.
     */
    @Autowired
    private JWTSigningAndValidationService jwtService;

    @RequestMapping(value = URL, produces = MediaType.APPLICATION_JSON_VALUE)
    @Override
    public String getJwk(final Model m) {
        final Map<String, JWK> keys = jwtService.getAllPublicKeys();
        m.addAttribute("keys", keys);
        return JWKSetView.VIEWNAME;
    }


}
