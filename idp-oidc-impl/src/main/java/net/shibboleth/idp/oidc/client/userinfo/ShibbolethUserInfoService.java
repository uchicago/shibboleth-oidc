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
package net.shibboleth.idp.oidc.client.userinfo;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.mitre.openid.connect.service.PairwiseIdentiferService;
import org.mitre.openid.connect.service.UserInfoService;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;


/**
 * The type Shibboleth user info service.
 * This component is almost identical to the default {@link org.mitre.openid.connect.service.impl.DefaultUserInfoService}
 * except that it has a concrete reference to the shibboleth userinfo repository implemented by OIDC  at {@link ShibbolethUserInfoRepository}
 * in order to retrieve userinfo values based on client id and username.
 */
@Service("openIdConnectUserInfoService")
@Primary
public class ShibbolethUserInfoService implements UserInfoService {
    /**
     * The Log.
     */
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    /**
     * The User info repository.
     */
    @Autowired
    @Qualifier("shibbolethUserInfoRepository")
    private ShibbolethUserInfoRepository userInfoRepository;

    /**
     * The Client service.
     */
    @Autowired
    private ClientDetailsEntityService clientService;

    /**
     * The Pairwise identifier service.
     */
    @Autowired
    private PairwiseIdentiferService pairwiseIdentifierService;

    @Override
    public UserInfo getByUsername(final String username) {
        return userInfoRepository.getByUsername(username);
    }

    @Override
    public UserInfo getByUsernameAndClientId(final String username, final String clientId) {

        log.debug("Locating client {} for username {}", clientId, username);

        final ClientDetailsEntity client = clientService.loadClientByClientId(clientId);
        final UserInfo userInfo = this.userInfoRepository.getByUsernameAndClientId(username, clientId);

        if (client == null || userInfo == null) {
            log.debug("No client or userinfo found for {} and {}", clientId, username);
            return null;
        }

        if (ClientDetailsEntity.SubjectType.PAIRWISE.equals(client.getSubjectType())) {
            log.debug("Client subject type is set to use {}", client.getSubjectType());

            final String pairwiseSub = pairwiseIdentifierService.getIdentifier(userInfo, client);
            log.debug("Pairwise sub is calculated as {}", pairwiseSub);

            userInfo.setSub(pairwiseSub);
        }

        return userInfo;

    }

    @Override
    public UserInfo getByEmailAddress(final String email) {
        return userInfoRepository.getByEmailAddress(email);
    }
}
