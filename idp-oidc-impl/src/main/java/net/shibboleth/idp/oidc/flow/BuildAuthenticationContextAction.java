package net.shibboleth.idp.oidc.flow;

import com.google.common.base.Strings;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.oidc.config.OidcConstants;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builds an authentication context message from an incoming request.
 */
public class BuildAuthenticationContextAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(BuildAuthenticationContextAction.class);

    private List<AuthenticationFlowDescriptor> availableAuthenticationFlows;

    private Map<AuthnContextClassRefPrincipal, Integer> authenticationPrincipalWeightMap;

    /**
     * Instantiates a new authentication context action.
     */
    public BuildAuthenticationContextAction() {
    }

    public void setAvailableAuthenticationFlows(final List<AuthenticationFlowDescriptor> availableAuthenticationFlows) {
        this.availableAuthenticationFlows = availableAuthenticationFlows;
    }

    public void setAuthenticationPrincipalWeightMap(final Map<AuthnContextClassRefPrincipal, Integer> authenticationPrincipalWeightMap) {
        this.authenticationPrincipalWeightMap = authenticationPrincipalWeightMap;
    }


    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        log.debug("{} Building authentication context", getLogPrefix());
        final AuthenticationContext ac = new AuthenticationContext();

        final OidcAuthorizationRequestContext authZContext = profileRequestContext.getSubcontext(OidcAuthorizationRequestContext.class);
        if (authZContext == null) {
            log.warn("No authorization request could be located in the profile request context");
            return Events.Failure.event(this);
        }

        final AuthorizationRequest authorizationRequest = authZContext.getAuthorizationRequest();
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
        return Events.Success.event(this);
    }
}
