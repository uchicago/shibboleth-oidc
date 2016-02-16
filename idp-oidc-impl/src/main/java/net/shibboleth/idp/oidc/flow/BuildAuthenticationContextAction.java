package net.shibboleth.idp.oidc.flow;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.google.common.base.Strings;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.oidc.config.OidcConstants;
import net.shibboleth.idp.oidc.util.OidcUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;
import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builds an authentication context message from an incoming request.
 */
public class BuildAuthenticationContextAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(BuildAuthenticationContextAction.class);

    @Nonnull private Function<ProfileRequestContext,AuthnRequest> requestLookupStrategy;

    @Nullable
    private AuthnRequest authnRequest;

    private List<AuthenticationFlowDescriptor> availableAuthenticationFlows;

    private Map<AuthnContextClassRefPrincipal, Integer> authenticationPrincipalWeightMap;

    /**
     * Instantiates a new authentication context action.
     */
    public BuildAuthenticationContextAction() {
        requestLookupStrategy =
                Functions.compose(new MessageLookup<>(AuthnRequest.class), new InboundMessageContextLookup());
    }

    public void setAvailableAuthenticationFlows(final List<AuthenticationFlowDescriptor> availableAuthenticationFlows) {
        this.availableAuthenticationFlows = availableAuthenticationFlows;
    }

    public void setAuthenticationPrincipalWeightMap(final Map<AuthnContextClassRefPrincipal, Integer> authenticationPrincipalWeightMap) {
        this.authenticationPrincipalWeightMap = authenticationPrincipalWeightMap;
    }

    /**
     * Sets request lookup strategy.
     *
     * @param strategy the strategy
     */
    public void setRequestLookupStrategy(@Nonnull final Function<ProfileRequestContext,AuthnRequest> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        requestLookupStrategy = Constraint.isNotNull(strategy, "AuthnRequest lookup strategy cannot be null");
    }


    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        authnRequest = requestLookupStrategy.apply(profileRequestContext);
        if (authnRequest == null) {
            log.debug("{} No inbound AuthnRequest, passive and forced flags will be off", getLogPrefix());
        }

        return super.doPreExecute(profileRequestContext);
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        log.debug("{} Building authentication context", getLogPrefix());
        final AuthenticationContext ac = new AuthenticationContext();
        if (authnRequest != null) {
            ac.setForceAuthn(authnRequest.isForceAuthn());
            ac.setIsPassive(authnRequest.isPassive());
        }

        final HttpServletRequest request = HttpServletRequestResponseContext.getRequest();
        final AuthorizationRequest authorizationRequest = OidcUtils.getAuthorizationRequest(request);
        if (authorizationRequest == null || Strings.isNullOrEmpty(authorizationRequest.getClientId())) {
            log.warn("Authorization request could not be loaded from session");
            return Events.Failure.event(this);
        }

        final List<Principal> principals = new ArrayList<>();
        if (authorizationRequest.getExtensions().containsKey(OidcConstants.ACR_VALUES)) {
            final String[] acrValues = authorizationRequest.getExtensions().get(OidcConstants.ACR_VALUES).toString().split(" ");
            for (final String acrValue : acrValues) {
                final AuthnContextClassRefPrincipal requestedPrincipal = new AuthnContextClassRefPrincipal(acrValue.trim());
                for (final AuthenticationFlowDescriptor flow : this.availableAuthenticationFlows) {
                    if (!principals.contains(requestedPrincipal) && flow.getSupportedPrincipals().contains(requestedPrincipal)) {
                        principals.add(requestedPrincipal);
                    }
                }
            }

        }

        if (principals.isEmpty()) {
            final AuthnContextClassRefPrincipal requestedPrincipal =
                    new AuthnContextClassRefPrincipal("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
            principals.add(requestedPrincipal);
        }

        final RequestedPrincipalContext rpc = new RequestedPrincipalContext();
        rpc.setOperator("exact");
        rpc.setRequestedPrincipals(principals);
        ac.addSubcontext(rpc, true);


        profileRequestContext.addSubcontext(ac, true);
        profileRequestContext.setBrowserProfile(true);
        return Events.Proceed.event(this);
    }
}
