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

import com.google.common.base.Strings;
import net.shibboleth.idp.attribute.EmptyAttributeValue;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.filter.AttributeFilter;
import net.shibboleth.idp.attribute.filter.context.AttributeFilterContext;
import net.shibboleth.idp.attribute.resolver.AttributeResolver;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.oidc.OIDCException;
import net.shibboleth.utilities.java.support.service.ReloadableService;
import org.mitre.openid.connect.model.DefaultAddress;
import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Repository;

import java.util.Map;

/**
 * The type Shibboleth user info repository.
 */
@Repository("shibbolethUserInfoRepository")
@Primary
public class ShibbolethUserInfoRepository implements UserInfoRepository {
    /**
     * The Log.
     */
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Autowired
    @Qualifier("shibboleth.AttributeResolverService")
    private ReloadableService<AttributeResolver> attributeResolverService;

    @Autowired
    @Qualifier("shibboleth.AttributeFilterService")
    private ReloadableService<AttributeFilter> attributeFilterService;

    @Override
    public UserInfo getByUsername(final String username) {
        return getByUsernameAndClientId(username, null);
    }

    public UserInfo getByUsernameAndClientId(final String username, final String recipientId) {
        final DefaultUserInfo userInfo = new DefaultUserInfo();
        log.debug("Set userinfo preferred username to {}", username);
        userInfo.setPreferredUsername(username);

        log.debug("Set userinfo sub claim to {}", username);
        userInfo.setSub(username);

        final AttributeResolver resolver = (AttributeResolver) this.attributeResolverService.getServiceableComponent();
        if (resolver == null) {
            log.error("Could not determine the attribute resolver service from context");
            return userInfo;
        }
        final AttributeFilter filter = (AttributeFilter) this.attributeFilterService.getServiceableComponent();
        if (filter == null) {
            log.error("Could not determine the attribute filter service from context");
            return userInfo;
        }

        try {
            final AttributeResolutionContext attributeContext = new AttributeResolutionContext();
            attributeContext.setPrincipal(username);
            attributeContext.setAttributeIssuerID(getClass().getSimpleName());
            attributeContext.setAllowCachedResults(true);
            attributeContext.setAttributeRecipientID(recipientId);
            resolver.resolveAttributes(attributeContext);
            final Map<String, IdPAttribute> resolvedAttributes = attributeContext.getResolvedIdPAttributes();

            final AttributeFilterContext filterContext = new AttributeFilterContext();
            filterContext.setPrincipal(username);
            filterContext.setAttributeIssuerID(getClass().getSimpleName());
            filterContext.setPrefilteredIdPAttributes(resolvedAttributes.values());
            filterContext.setAttributeRecipientID(recipientId);
            filter.filterAttributes(filterContext);

            final Map<String, IdPAttribute> filteredAttributes = filterContext.getFilteredIdPAttributes();
            for (final String attributeKey : filteredAttributes.keySet()) {
                final IdPAttribute attribute = filteredAttributes.get(attributeKey);
                log.debug("Attribute {} is authorized for release. Mapping...", attribute.getId());
                setUserInfoClaimByAttribute(username, userInfo, attribute);
            }
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
        }

        if (Strings.isNullOrEmpty(userInfo.getSub())) {
            log.warn("userinfo sub claim cannot be null/empty. Reset claim value to {}", username);
            userInfo.setSub(username);
        }
        log.debug("Final userinfo object constructed from attributes is\n {}", userInfo.toJson());
        return userInfo;
    }

    @Override
    public UserInfo getByEmailAddress(final String s) {
        throw new OIDCException("Operation is not supported");
    }
    
    /**
     * Sets user info claim by attribute.
     *
     * @param principal the principal
     * @param userInfo  the user info
     * @param attribute the attribute
     */
    private void setUserInfoClaimByAttribute(final String principal,
                                             final DefaultUserInfo userInfo,
                                             final IdPAttribute attribute) {
        switch (attribute.getId()) {
            case "sub":
                userInfo.setSub(getAttributeValue(attribute).getValue().toString());
                log.debug("Overriding existing sub value {} to {}", principal, userInfo.getSub());
                break;
            case "name":
                userInfo.setName(getAttributeValue(attribute).getValue().toString());
                break;
            case "given_name":
                userInfo.setGivenName(getAttributeValue(attribute).getValue().toString());
                break;
            case "family_name":
                userInfo.setFamilyName(getAttributeValue(attribute).getValue().toString());
                break;
            case "middle_name":
                userInfo.setMiddleName(getAttributeValue(attribute).getValue().toString());
                break;
            case "nickname":
                userInfo.setNickname(getAttributeValue(attribute).getValue().toString());
                break;
            case "preferred_username":
                userInfo.setPreferredUsername(getAttributeValue(attribute).getValue().toString());
                break;
            case "profile":
                userInfo.setProfile(getAttributeValue(attribute).getValue().toString());
                break;
            case "picture":
                userInfo.setPicture(getAttributeValue(attribute).getValue().toString());
                break;
            case "website":
                userInfo.setWebsite(getAttributeValue(attribute).getValue().toString());
                break;
            case "email":
                userInfo.setEmail(getAttributeValue(attribute).getValue().toString());
                break;
            case "email_verified":
                userInfo.setEmailVerified(Boolean.valueOf(getAttributeValue(attribute).getValue().toString()));
                break;
            case "gender":
                userInfo.setGender(getAttributeValue(attribute).getValue().toString());
                break;
            case "birthdate":
                userInfo.setBirthdate(getAttributeValue(attribute).getValue().toString());
                break;
            case "zoneinfo":
                userInfo.setZoneinfo(getAttributeValue(attribute).getValue().toString());
                break;
            case "locale":
                userInfo.setLocale(getAttributeValue(attribute).getValue().toString());
                break;
            case "phone_number":
                userInfo.setPhoneNumber(getAttributeValue(attribute).getValue().toString());
                break;
            case "phone_number_verified":
                userInfo.setPhoneNumberVerified(
                    Boolean.valueOf(getAttributeValue(attribute).getValue().toString()));
                break;
            case "updated_at":
                userInfo.setUpdatedTime(getAttributeValue(attribute).getValue().toString());
                break;
            case "address":
                final DefaultAddress address = new DefaultAddress();
                address.setFormatted(getAttributeValue(attribute).getValue().toString());
                userInfo.setAddress(address);
                break;
            default:
                log.warn("Unrecognized claim {} ignored.", attribute.getId());
        }
    }

    /**
     * Gets attribute value.
     *
     * @param attribute the attribute
     * @return the attribute value
     */
    protected IdPAttributeValue<?> getAttributeValue(final IdPAttribute attribute) {
        if (!attribute.getValues().isEmpty()) {
            return attribute.getValues().get(0);
        }
        return new EmptyAttributeValue(EmptyAttributeValue.EmptyType.NULL_VALUE);
    }


}
