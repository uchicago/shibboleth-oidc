package net.shibboleth.idp.oidc.flow;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.consent.context.AttributeReleaseContext;
import net.shibboleth.idp.oidc.OpenIdConnectUtils;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import java.util.Map;

/**
 *
 */
public class PostAuthorizationUserApprovalAction extends AbstractProfileAction {
    private final Logger log = LoggerFactory.getLogger(PreAuthorizeUserApprovalAction.class);

    public PostAuthorizationUserApprovalAction() {
    }

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull RequestContext springRequestContext,
                              @Nonnull ProfileRequestContext profileRequestContext) {
        AttributeReleaseContext context = profileRequestContext.getSubcontext(AttributeReleaseContext.class);
        Map<String, IdPAttribute> attributes = context.getConsentableAttributes();
        AuthorizationRequest request =
                OpenIdConnectUtils.getAuthorizationRequest(HttpServletRequestResponseContext.getRequest());
        OpenIdConnectResponse response = OpenIdConnectUtils.getResponse(springRequestContext);
        
        return super.doExecute(springRequestContext, profileRequestContext);
    }
}
