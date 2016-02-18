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
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.stereotype.Repository;

import java.util.Map;

@Repository("shibbolethUserInfoRepository")
@Primary
public class ShibbolethUserInfoRepository implements UserInfoRepository {
    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    private ProfileRequestContext profileRequestContext;

    public void initialize(final ProfileRequestContext prc) {
        this.profileRequestContext = prc;
    }

    public SubjectContext getSubjectContext() {
        return profileRequestContext.getSubcontext(SubjectContext.class);
    }

    public ConsentContext getConsentContext() {
        return profileRequestContext.getSubcontext(ConsentContext.class);
    }

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

                    switch (attribute.getId()) {
                        case "sub":
                            log.debug("Overriding existing sub claim {} to attribute value {}", principal.getPrincipalName());
                            userInfo.setSub(getAttributeValue(attribute).getValue().toString());
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
                            userInfo.setPhoneNumberVerified(Boolean.valueOf(getAttributeValue(attribute).getValue().toString()));
                            break;
                        case "updated_at":
                            userInfo.setUpdatedTime(getAttributeValue(attribute).getValue().toString());
                            break;
                        case "address":
                            final DefaultAddress address = new DefaultAddress();
                            address.setFormatted(getAttributeValue(attribute).getValue().toString());
                            userInfo.setAddress(address);
                            break;

                    }

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

    protected IdPAttributeValue<?> getAttributeValue(final IdPAttribute attribute) {
        if (!attribute.getValues().isEmpty()) {
            return attribute.getValues().get(0);
        }
        return new EmptyAttributeValue(EmptyAttributeValue.EmptyType.NULL_VALUE);
    }

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
