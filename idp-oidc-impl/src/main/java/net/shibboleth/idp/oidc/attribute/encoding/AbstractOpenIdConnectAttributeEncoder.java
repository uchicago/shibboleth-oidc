/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.shibboleth.idp.oidc.attribute.encoding;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.gson.JsonObject;
import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.component.UnmodifiableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.Objects;

/**
 * The type Open id connect attribute encoder.
 * @param <AttributeType>    the type parameter
 * @param <EncodedType>  the type parameter
 */
public abstract class AbstractOpenIdConnectAttributeEncoder<AttributeType extends JsonObject,
        EncodedType extends IdPAttributeValue> extends AbstractInitializableComponent
        implements AttributeEncoder<AttributeType>, UnmodifiableComponent {

    /**
     * The Log.
     */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractOpenIdConnectAttributeEncoder.class);

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
        } else if(!(obj instanceof AbstractOpenIdConnectAttributeEncoder)) {
            return false;
        } else {
            final AbstractOpenIdConnectAttributeEncoder other = (AbstractOpenIdConnectAttributeEncoder)obj;
            return Objects.equals(getName(), other.getName())
                    && Objects.equals(getProtocol(), other.getProtocol());
        }
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(new Object[]{getName(), getProtocol()});
    }

}
