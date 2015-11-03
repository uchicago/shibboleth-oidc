package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.consent.context.impl.ConsentContext;
import net.shibboleth.idp.consent.impl.Consent;
import net.shibboleth.idp.oidc.util.OpenIdConnectUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * An action to handle the user approval/consent post authorization.
 */
public class PostAuthorizationUserApprovalAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(PreAuthorizeUserApprovalAction.class);

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {

        final HttpServletRequest request = HttpServletRequestResponseContext.getRequest();
        final Map map = new HashMap<>();
        map.put("_csrf", request.getAttribute("_csrf"));

        final ConsentContext context = profileRequestContext.getSubcontext(ConsentContext.class);
        final Map<String, Consent> attributes = context.getCurrentConsents();
        final AuthorizationRequest authorizationRequest =
                OpenIdConnectUtils.getAuthorizationRequest(HttpServletRequestResponseContext.getRequest());
        final OpenIdConnectResponse response = OpenIdConnectUtils.getResponse(springRequestContext);

        springRequestContext.getViewScope().put("postAuthorizationAttributes", map);
        return super.doExecute(springRequestContext, profileRequestContext);
    }
}
