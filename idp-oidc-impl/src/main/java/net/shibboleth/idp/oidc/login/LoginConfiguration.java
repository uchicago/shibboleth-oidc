package net.shibboleth.idp.oidc.login;

import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import net.shibboleth.idp.authn.config.AuthenticationProfileConfiguration;
import net.shibboleth.idp.profile.config.AbstractProfileConfiguration;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import javax.annotation.Nonnull;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * OIDC protocol configuration that applies to the <code>/login</code> URI.
 */
public class LoginConfiguration extends AbstractProfileConfiguration implements AuthenticationProfileConfiguration {
    /**
     * The profile identifier.
     */
    public static final String PROFILE_ID = "http://openid.net/connect/login";

    private boolean resolveAttributes = true;

    @Nonnull
    @NonnullElements
    private Set<String> authenticationFlows = Collections.emptySet();
    @Nonnull
    @NonnullElements
    private List<String> postAuthenticationFlows = Collections.emptyList();
    @Nonnull
    @NonnullElements
    private List<AuthnContextClassRefPrincipal> defaultAuthenticationContexts = Collections.emptyList();
    @Nonnull
    @NonnullElements
    private List<String> nameIDFormatPrecedence = Collections.emptyList();

    /**
     * Instantiates a new login configuration instance.
     * Sets the profile identifier to {@link #PROFILE_ID}.
     */
    public LoginConfiguration() {
        super(PROFILE_ID);
    }

    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<Principal> getDefaultAuthenticationMethods() {
        return ImmutableList.copyOf(this.defaultAuthenticationContexts);
    }

    /**
     * Sets default authentication methods.
     *
     * @param contexts the contexts
     */
    public void setDefaultAuthenticationMethods(
            @Nonnull @NonnullElements final List<AuthnContextClassRefPrincipal> contexts) {
        Constraint.isNotNull(contexts, "List of contexts cannot be null");
        this.defaultAuthenticationContexts = new ArrayList(Collections2.filter(contexts, Predicates.notNull()));
    }

    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public Set<String> getAuthenticationFlows() {
        return ImmutableSet.copyOf(this.authenticationFlows);
    }

    /**
     * Sets authentication flows.
     *
     * @param flows the flows
     */
    public void setAuthenticationFlows(@Nonnull @NonnullElements final Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");
        this.authenticationFlows = new HashSet(Collections2.filter(flows, Predicates.notNull()));
    }

    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getPostAuthenticationFlows() {
        return this.postAuthenticationFlows;
    }

    /**
     * Sets post authentication flows.
     *
     * @param flows the flows
     */
    public void setPostAuthenticationFlows(@Nonnull @NonnullElements final Collection<String> flows) {
        Constraint.isNotNull(flows, "Collection of flows cannot be null");
        this.postAuthenticationFlows = new ArrayList(StringSupport.normalizeStringCollection(flows));
    }

    @Override
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getNameIDFormatPrecedence() {
        return ImmutableList.copyOf(this.nameIDFormatPrecedence);
    }

    /**
     * Sets name iD format precedence.
     *
     * @param formats the formats
     */
    public void setNameIDFormatPrecedence(@Nonnull @NonnullElements final List<String> formats) {
        Constraint.isNotNull(formats, "List of formats cannot be null");
        this.nameIDFormatPrecedence = new ArrayList(Collections2.filter(formats, Predicates.notNull()));
    }

    /**
     * Are we resolving attributes for this profile?
     *
     * @return true/false
     */
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public boolean isResolveAttributes() {
        return resolveAttributes;
    }

    /**
     * Sets resolve attributes.
     *
     * @param resolve the resolve attributes
     */
    public void setResolveAttributes(final boolean resolve) {
        resolveAttributes = resolve;
    }
}
