/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package net.shibboleth.idp.oidc.config;

import com.google.common.base.Function;
import javax.annotation.Nullable;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import org.opensaml.profile.context.ProfileRequestContext;

/**
 * Looks up the {@link RelyingPartyContext}
 * and makes sure the config class provided is an instance
 * of the profile configuration provided by that context.
 * @param <T>  the type parameter
 */
public class ConfigLookupFunction<T> implements Function<ProfileRequestContext, T> {
    private final Class<T> configClass;

    /**
     * Instantiates a Config lookup function.
     *
     * @param clazz the clazz
     */
    public ConfigLookupFunction(final Class<T> clazz) {
        this.configClass = clazz;
    }

    @Nullable
    @Override
    public T apply(@Nullable final ProfileRequestContext profileRequestContext) {
        if(profileRequestContext != null) {
            final RelyingPartyContext rpContext = profileRequestContext.getSubcontext(RelyingPartyContext.class, false);
            if(rpContext != null && this.configClass.isInstance(rpContext.getProfileConfig())) {
                return this.configClass.cast(rpContext.getProfileConfig());
            }
        }

        return null;
    }
}
