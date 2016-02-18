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
package net.shibboleth.idp.oidc.client;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.repository.OAuth2ClientRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * The type Shibboleth o auth 2 client repository.
 */
@Component("shibbolethOAuth2ClientRepository")
@Primary
public class ShibbolethOAuth2ClientRepository implements OAuth2ClientRepository {

    /**
     * The Clients.
     */
    @Resource(name="oidcClients")
    private Set<ClientDetailsEntity> clients = new HashSet<>();

    /**
     * Instantiates a new Shibboleth o auth 2 client repository.
     */
    protected ShibbolethOAuth2ClientRepository() {}

    /**
     * Instantiates a new Shibboleth o auth 2 client repository.
     *
     * @param registeredClients the registered clients
     */
    public ShibbolethOAuth2ClientRepository(final Set<ClientDetailsEntity> registeredClients) {
        this.clients = registeredClients;
    }

    @Override
    public ClientDetailsEntity getById(final Long aLong) {
        for (final ClientDetailsEntity client : clients) {
            if (client.getId().equals(aLong)) {
                return client;
            }
        }
        return null;
    }

    @Override
    public ClientDetailsEntity getClientByClientId(final String s) {
        for (final ClientDetailsEntity client : clients) {
            if (client.getClientId().equals(s)) {
                return client;
            }
        }
        return null;
    }

    @Override
    public ClientDetailsEntity saveClient(final ClientDetailsEntity clientDetailsEntity) {
        clients.add(clientDetailsEntity);
        return clientDetailsEntity;
    }

    @Override
    public void deleteClient(final ClientDetailsEntity clientDetailsEntity) {
        clients.remove(clientDetailsEntity);
    }

    @Override
    public ClientDetailsEntity updateClient(final Long aLong, final ClientDetailsEntity clientDetailsEntity) {
        return saveClient(clientDetailsEntity);
    }

    @Override
    public Collection<ClientDetailsEntity> getAllClients() {
        return clients;
    }
}
