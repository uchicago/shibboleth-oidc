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
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.consent.context.impl.AttributeReleaseContext;
import net.shibboleth.idp.consent.context.impl.ConsentContext;
import net.shibboleth.idp.consent.impl.Consent;
import net.shibboleth.idp.oidc.OIDCException;
import org.mitre.openid.connect.model.DefaultAddress;
import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    /**
     * The Profile request context.
     */
    private ProfileRequestContext profileRequestContext;

    /**
     * Initialize.
     *
     * @param prc the prc
     */
    public void initialize(final ProfileRequestContext prc) {
        this.profileRequestContext = prc;
    }

    /**
     * Gets subject context.
     *
     * @return the subject context
     */
    public SubjectContext getSubjectContext() {
        return profileRequestContext.getSubcontext(SubjectContext.class);
    }

    /**
     * Gets consent context.
     *
     * @return the consent context
     */
    public ConsentContext getConsentContext() {
        return profileRequestContext.getSubcontext(ConsentContext.class);
    }

    /**
     * Gets attribute release context.
     *
     * @return the attribute release context
     */
    public AttributeReleaseContext getAttributeReleaseContext() {
        return profileRequestContext.getSubcontext(AttributeReleaseContext.class);
    }

    @Override
    public UserInfo getByUsername(final String s) {
        final SubjectContext principal = getSubjectContext();

        if (principal == null || principal.getPrincipalName() == null) {
            throw new OIDCException("No SubjectContext found in the profile request context");
        }
        final DefaultUserInfo userInfo = new DefaultUserInfo();
        log.debug("Set userinfo preferred username to {}", principal.getPrincipalName());
        userInfo.setPreferredUsername(principal.getPrincipalName());

        log.debug("Set userinfo sub claim to {}", principal.getPrincipalName());
        userInfo.setSub(principal.getPrincipalName());

        log.debug("Setting preferred username to {}", principal.getPrincipalName());

        if (getAttributeReleaseContext() != null) {
            log.debug("Found attribute release context. Locating consentable attributes...");

            final Map<String, IdPAttribute> consentableAttributes = getAttributeReleaseContext().getConsentableAttributes();
            log.debug("Consentable attributes are {}", consentableAttributes.keySet());

            for (final String attributeKey : consentableAttributes.keySet()) {
                final IdPAttribute attribute = consentableAttributes.get(attributeKey);
                log.debug("Processing userinfo claim for attribute {}", attributeKey);

                final boolean releaseAttribute = getConsentContext() == null || consentedToAttributeRelease(attribute);
                if (releaseAttribute) {
                    log.debug("Attribute {} is authorized for release. Mapping...", attribute.getId());
                    setUserInfoClaimByAttribute(principal, userInfo, attribute);
                }
            }
        }

        if (Strings.isNullOrEmpty(userInfo.getSub())) {
            log.warn("userinfo sub claim cannot be null/empty. Reset claim value to {}", principal.getPrincipalName());
            userInfo.setSub(principal.getPrincipalName());
        }
        log.debug("Final userinfo object constructed from attributes is\n {}", userInfo.toJson());
        return userInfo;
    }

    /**
     * Sets user info claim by attribute.
     *
     * @param principal the principal
     * @param userInfo  the user info
     * @param attribute the attribute
     */
    private void setUserInfoClaimByAttribute(final SubjectContext principal,
                                             final DefaultUserInfo userInfo,
                                             final IdPAttribute attribute) {
        switch (attribute.getId()) {
            case "sub":
                userInfo.setSub(getAttributeValue(attribute).getValue().toString());
                log.debug("Overriding existing sub value {} to {}", principal.getPrincipalName(), userInfo.getSub());
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

    /**
     * Consented to attribute release boolean.
     *
     * @param attribute the attribute
     * @return the boolean
     */
    private boolean consentedToAttributeRelease(final IdPAttribute attribute) {
        final Map<String, Consent> consents = getConsentContext().getCurrentConsents();
        return consents.containsKey(attribute.getId()) &&
                consents.get(attribute.getId()).isApproved();
    }

    @Override
    public UserInfo getByEmailAddress(final String s) {
        throw new OIDCException("Operation is not supported");
    }
}
