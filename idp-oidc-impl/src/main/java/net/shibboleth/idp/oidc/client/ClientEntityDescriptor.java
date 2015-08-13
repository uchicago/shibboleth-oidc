package net.shibboleth.idp.oidc.client;

import net.shibboleth.utilities.java.support.collection.LockableClassToInstanceMultiMap;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import org.joda.time.DateTime;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.NamespaceManager;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.util.AttributeMap;
import org.opensaml.core.xml.util.IDIndex;
import org.opensaml.saml.metadata.EntityGroupName;
import org.opensaml.saml.saml2.metadata.AdditionalMetadataLocation;
import org.opensaml.saml.saml2.metadata.AffiliationDescriptor;
import org.opensaml.saml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml.saml2.metadata.AuthnAuthorityDescriptor;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xmlsec.signature.Signature;
import org.w3c.dom.Element;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class ClientEntityDescriptor implements EntityDescriptor {
    private String clientId;

    @Nonnull
    private LockableClassToInstanceMultiMap<Object> objectMetadata;

    public ClientEntityDescriptor(@Nonnull String clientIdentifier) {
        this.clientId = Constraint.isNotNull(clientIdentifier, "Client cannot be null");
        this.objectMetadata = new LockableClassToInstanceMultiMap(true);
    }

    public String getEntityID() {
        return clientId;
    }

    public void setEntityID(String id) {
        throw new UnsupportedOperationException();
    }

    public String getID() {
        return clientId;
    }

    public void setID(String newID) {
        throw new UnsupportedOperationException();
    }

    public Extensions getExtensions() {
        return null;
    }

    public void setExtensions(Extensions extensions) {
        throw new UnsupportedOperationException();
    }

    public List<RoleDescriptor> getRoleDescriptors() {
        return Collections.emptyList();
    }

    public List<RoleDescriptor> getRoleDescriptors(QName typeOrName) {
        return Collections.emptyList();
    }

    public List<RoleDescriptor> getRoleDescriptors(QName typeOrName, String supportedProtocol) {
        return Collections.emptyList();
    }

    public IDPSSODescriptor getIDPSSODescriptor(String supportedProtocol) {
        return null;
    }

    public SPSSODescriptor getSPSSODescriptor(String supportedProtocol) {
        return null;
    }

    public AuthnAuthorityDescriptor getAuthnAuthorityDescriptor(String supportedProtocol) {
        return null;
    }

    public AttributeAuthorityDescriptor getAttributeAuthorityDescriptor(String supportedProtocol) {
        return null;
    }

    public PDPDescriptor getPDPDescriptor(String supportedProtocol) {
        return null;
    }

    public AffiliationDescriptor getAffiliationDescriptor() {
        return null;
    }

    public void setAffiliationDescriptor(AffiliationDescriptor descriptor) {
        throw new UnsupportedOperationException();
    }

    public Organization getOrganization() {
        return null;
    }

    public void setOrganization(Organization organization) {
        throw new UnsupportedOperationException();
    }

    public List<ContactPerson> getContactPersons() {
        return Collections.emptyList();
    }

    public List<AdditionalMetadataLocation> getAdditionalMetadataLocations() {
        return Collections.emptyList();
    }

    @Nonnull
    public AttributeMap getUnknownAttributes() {
        return null;
    }

    public Long getCacheDuration() {
        return null;
    }

    public void setCacheDuration(Long duration) {
        throw new UnsupportedOperationException();
    }

    @Nullable
    public String getSignatureReferenceID() {
        return null;
    }

    public boolean isSigned() {
        return false;
    }

    @Nullable
    public Signature getSignature() {
        return null;
    }

    public void setSignature(@Nullable Signature newSignature) {
        throw new UnsupportedOperationException();
    }

    public boolean isValid() {
        return true;
    }

    public DateTime getValidUntil() {
        return DateTime.now().plusDays(1);
    }

    public void setValidUntil(DateTime validUntil) {
        throw new UnsupportedOperationException();
    }

    public void detach() {
    }

    @Nullable
    public Element getDOM() {
        return null;
    }

    @Nonnull
    public QName getElementQName() {
        return new QName("http://openid.net/connect", "oidc");
    }

    @Nonnull
    public IDIndex getIDIndex() {
        return null;
    }

    @Nonnull
    public NamespaceManager getNamespaceManager() {
        return null;
    }

    @Nonnull
    public Set<Namespace> getNamespaces() {
        return Collections.emptySet();
    }

    @Nullable
    public String getNoNamespaceSchemaLocation() {
        return null;
    }

    @Nullable
    public List<XMLObject> getOrderedChildren() {
        return Collections.emptyList();
    }

    @Nullable
    public XMLObject getParent() {
        return null;
    }

    @Nullable
    public String getSchemaLocation() {
        return null;
    }

    @Nullable
    public QName getSchemaType() {
        return null;
    }

    public boolean hasChildren() {
        return false;
    }

    public boolean hasParent() {
        return false;
    }

    public void releaseChildrenDOM(boolean propagateRelease) {
    }

    public void releaseDOM() {
    }

    public void releaseParentDOM(boolean propagateRelease) {
    }

    @Nullable
    public XMLObject resolveID(@Nonnull String id) {
        return null;
    }

    @Nullable
    public XMLObject resolveIDFromRoot(@Nonnull String id) {
        return null;
    }

    public void setDOM(@Nullable Element dom) {
        throw new UnsupportedOperationException();
    }

    public void setNoNamespaceSchemaLocation(@Nullable String location) {
        throw new UnsupportedOperationException();
    }

    public void setParent(@Nullable XMLObject parent) {
        throw new UnsupportedOperationException();
    }

    public void setSchemaLocation(@Nullable String location) {
        throw new UnsupportedOperationException();
    }

    @Nullable
    public Boolean isNil() {
        return Boolean.valueOf(false);
    }

    @Nullable
    public XSBooleanValue isNilXSBoolean() {
        return null;
    }

    public void setNil(@Nullable Boolean newNil) {
        throw new UnsupportedOperationException();
    }

    public void setNil(@Nullable XSBooleanValue newNil) {
        throw new UnsupportedOperationException();
    }

    @Nonnull
    public LockableClassToInstanceMultiMap<Object> getObjectMetadata() {
        return this.objectMetadata;
    }
}

