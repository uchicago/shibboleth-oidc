package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.oidc.OIDCException;
import net.shibboleth.idp.oidc.util.OIDCUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private final Logger log = LoggerFactory.getLogger(PostAuthorizationUserApprovalAction.class);

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
                              @Nonnull final ProfileRequestContext profileRequestContext) {
        final HttpServletRequest request = OIDCUtils.getHttpServletRequest(springRequestContext);
        if (request == null) {
            throw new OIDCException("HttpServletRequest cannot be null");
        }

        final OIDCAuthorizationRequestContext authZContext = profileRequestContext.getSubcontext(OIDCAuthorizationRequestContext.class);
        if (authZContext == null) {
            log.warn("No authorization request could be located in the profile request context");
            return Events.Failure.event(this);
        }

        final OIDCAuthorizationResponseContext responseCtx = profileRequestContext.getSubcontext(OIDCAuthorizationResponseContext.class);
        if (responseCtx == null) {
            log.warn("No response context could be located in the profile request context");
            return Events.Failure.event(this);
        }
        final Object csrf = request.getAttribute("_csrf");
        if (csrf == null) {
            log.warn("CSRF attribute could not be found in the request");
            return Events.Failure.event(this);
        }

        final Map map = new HashMap<>();
        map.put("_csrf", csrf);
        springRequestContext.getViewScope().put("postAuthorizationAttributes", map);
        springRequestContext.getViewScope().put("authorizationRequest", authZContext.getAuthorizationRequest());
        springRequestContext.getViewScope().put("oidcResponse", responseCtx.getOidcResponse());
        springRequestContext.getViewScope().put("csrf", csrf);

        /**
         * This is required for the authorization endpoint of Spring Security, as it needs
         * the authZ request to be a session attribute.
         */
        OIDCUtils.putSessionAttribute(request, "authorizationRequest", authZContext.getAuthorizationRequest());
        return super.doExecute(springRequestContext, profileRequestContext);
    }
}
