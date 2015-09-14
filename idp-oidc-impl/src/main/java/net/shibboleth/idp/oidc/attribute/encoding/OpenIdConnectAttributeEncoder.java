package net.shibboleth.idp.oidc.attribute.encoding;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.gson.JsonObject;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.component.UnmodifiableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/**
 * The type Open id connect attribute encoder.
 * @param <AttributeType>   the type parameter
 * @param <Attribute>  the type parameter
 */

public abstract class OpenIdConnectAttributeEncoder<AttributeType extends JsonObject,
        EncodedType extends IdPAttributeValue> extends AbstractInitializableComponent
        implements AttributeEncoder<AttributeType>, UnmodifiableComponent {

    /**
     * The Log.
     */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OpenIdConnectAttributeEncoder.class);

    /**
     * The Activation condition.
     */
    @Nonnull
    private Predicate<ProfileRequestContext> activationCondition = Predicates.alwaysTrue();

    /**
     * The Name.
     */
    @NonnullAfterInit
    private String name;

    /**
     * Gets name.
     *
     * @return the name
     */
    @NonnullAfterInit
    public final String getName() {
        return this.name;
    }

    /**
     * Sets name.
     *
     * @param attributeName the attribute name
     */
    public void setName(@Nonnull @NotEmpty final String attributeName) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        this.name = Constraint.isNotNull(StringSupport.trimOrNull(attributeName),
                "Attribute name cannot be null or empty");
    }

    @Nonnull
    @Override
    public String getProtocol() {
        return "http://openid.net/connect";
    }

    @Nonnull
    @Override
    public Predicate<ProfileRequestContext> getActivationCondition() {
        return this.activationCondition;
    }

    /**
     * Sets activation condition.
     *
     * @param condition the condition
     */
    public void setActivationCondition(@Nonnull final Predicate<ProfileRequestContext> condition) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        this.activationCondition = (Predicate)Constraint.isNotNull(condition, "Activation condition cannot be null");
    }

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if(this.name == null) {
            throw new ComponentInitializationException("Attribute name cannot be null or empty");
        }

    }

    @Override
    public boolean equals(final Object obj) {
        if(obj == null) {
            return false;
        } else if(obj == this) {
            return true;
        } else if(!(obj instanceof OpenIdConnectAttributeEncoder)) {
            return false;
        } else {
            final OpenIdConnectAttributeEncoder other = (OpenIdConnectAttributeEncoder)obj;
            return Objects.equals(this.getName(), other.getName())
                    && Objects.equals(this.getProtocol(), other.getProtocol());
        }
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(new Object[]{this.getName(), this.getProtocol()});
    }

}
