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
package net.shibboleth.idp.oidc.config.scope;

import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.repository.SystemScopeRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.HashSet;
import java.util.Set;

/**
 * Repository to define system scopes statically.
 */
@Component("shibbolethSystemScopeRepository")
@Primary
public class ShibbolethSystemScopeRepository implements SystemScopeRepository {

    /**
     * The Scopes.
     */
    @Resource(name="supportedSystemScopes")
    private Set<SystemScope> scopes = new HashSet<>();

    /**
     * Instantiates a new Shibboleth system scope repository.
     */
    protected ShibbolethSystemScopeRepository() {}

    /**
     * Instantiates a new Shibboleth system scope repository.
     *
     * @param scs the scs
     */
    public ShibbolethSystemScopeRepository(final Set<SystemScope> scs) {
        this.scopes = scs;
    }

    @Override
    public Set<SystemScope> getAll() {
        return this.scopes;
    }

    @Override
    public SystemScope getById(final Long aLong) {
        for (final SystemScope scope : scopes) {
            if (scope.getId().equals(aLong)) {
                return scope;
            }
        }
        return null;
    }

    @Override
    public SystemScope getByValue(final String s) {
        for (final SystemScope scope : scopes) {
            if (scope.getValue().equals(s)) {
                return scope;
            }
        }
        return null;
    }

    @Override
    public void remove(final SystemScope systemScope) {
        this.scopes.remove(systemScope);
    }

    @Override
    public SystemScope save(final SystemScope systemScope) {
        this.scopes.add(systemScope);
        return systemScope;
    }

    /**
     * The entry point of application.
     *
     * @param args the input arguments
     */
    public static void main(String[] args) {
        System.out.println(Math.random());
    }
}
