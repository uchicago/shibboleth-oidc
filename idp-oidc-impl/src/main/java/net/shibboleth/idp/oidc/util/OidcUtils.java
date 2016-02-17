package net.shibboleth.idp.oidc.util;

import net.shibboleth.idp.oidc.endpoints.AuthorizeEndpoint;
import net.shibboleth.idp.oidc.endpoints.DynamicRegistrationEndpoint;
import net.shibboleth.idp.oidc.endpoints.IntrospectionEndpoint;
import net.shibboleth.idp.oidc.endpoints.JWKPublishingEndpoint;
import net.shibboleth.idp.oidc.endpoints.RevocationEndpoint;
import net.shibboleth.idp.oidc.endpoints.TokenEndpoint;
import net.shibboleth.idp.oidc.endpoints.UserInfoEndpoint;
import net.shibboleth.idp.oidc.flow.OidcResponse;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ui.Model;
import org.springframework.util.Assert;
import org.springframework.webflow.context.servlet.ServletExternalContext;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Date;
import java.util.Map;

/**
 * OpenId Connect Utility methods that deal with setting and removing
 * session data.
 */
public final class OidcUtils {
    /**
     * The constant PROMPTED.
     */
    private static final String PROMPTED = "PROMPT_FILTER_PROMPTED";

    /**
     * The constant PROMPT_REQUESTED.
     */
    private static final String PROMPT_REQUESTED = "PROMPT_FILTER_REQUESTED";

    /**
     * The constant LOG.
     */
    private static final Logger LOG = LoggerFactory.getLogger(OidcUtils.class);

    /**
     * Instantiates a new Open id connect utils.
     */
    private OidcUtils() {}

    /**
     * Sets request parameter.
     *
     * @param request the request
     * @param parameter the parameter
     * @param value the value
     */
    public static void setRequestParameter(final HttpServletRequest request,
                                 final String parameter,
                                 final Object value) {
        final HttpSession session = request.getSession();
        session.setAttribute(parameter, value);
    }

    /**
     * Remove session parameter.
     *
     * @param request the request
     * @param parameter the parameter
     */
    public static void removeSessionAttribute(final HttpServletRequest request,
                                              final String parameter) {
        final HttpSession session = request.getSession();
        session.removeAttribute(parameter);
    }

    /**
     * Remove request prompted.
     *
     * @param request the request
     */
    public static void removeRequestPrompted(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        session.removeAttribute(PROMPTED);
    }

    /**
     * Sets prompt requested.
     *
     * @param request the request
     */
    public static void setPromptRequested(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        session.setAttribute(PROMPT_REQUESTED, Boolean.TRUE);
    }

    /**
     * Is request prompted.
     *
     * @param request the request
     * @return the boolean
     */
    public static Boolean isRequestPrompted(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        return session.getAttribute(PROMPTED) == null;
    }

    /**
     * Gets authentication timestamp.
     *
     * @param request the request
     * @return the authentication timestamp
     */
    public static Date getAuthenticationTimestamp(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        return (Date) session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP);
    }

    /**
     * Gets the http servlet response from the context.
     *
     * @param context the context
     * @return the http servlet response
     */
    public static HttpServletResponse getHttpServletResponse(
            final RequestContext context) {
        Assert.isInstanceOf(ServletExternalContext.class, context
                        .getExternalContext(),
                "Cannot obtain HttpServletResponse from event of type: "
                        + context.getExternalContext().getClass().getName());
        return (HttpServletResponse) context.getExternalContext()
                .getNativeResponse();
    }

    /**
     * Gets the http servlet request from the context.
     *
     * @param context the context
     * @return the http servlet request
     */
    public static HttpServletRequest getHttpServletRequest(
            final RequestContext context) {
        Assert.isInstanceOf(ServletExternalContext.class, context
                        .getExternalContext(),
                "Cannot obtain HttpServletRequest from event of type: "
                        + context.getExternalContext().getClass().getName());

        return (HttpServletRequest) context.getExternalContext().getNativeRequest();
    }

    public static Map<String, Object> buildOidcServerConfigurationModelForDiscovery(final Model model) {
        final Map<String, Object> m = Map.class.cast(model.asMap().get("entity"));
        final String baseUrl = m.get("issuer").toString();
        m.put("authorization_endpoint", baseUrl + "profile" + AuthorizeEndpoint.URL);
        m.put("token_endpoint", baseUrl + "profile" + TokenEndpoint.URL);
        m.put("userinfo_endpoint", baseUrl + "profile" + UserInfoEndpoint.URL);
        m.put("jwks_uri", baseUrl + "profile" + JWKPublishingEndpoint.URL);
        m.put("revocation_endpoint", baseUrl + "profile" + RevocationEndpoint.URL);
        m.put("introspection_endpoint", baseUrl + "profile" + IntrospectionEndpoint.URL);
        m.put("registration_endpoint", baseUrl + "profile" + DynamicRegistrationEndpoint.URL);
        m.remove("service_documentation");
        m.remove("op_policy_uri");
        m.remove("op_tos_uri");
        return m;
    }
}
