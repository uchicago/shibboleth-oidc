<%@ taglib uri="urn:mace:shibboleth:2.0:idp:ui" prefix="idpui" %>
<%@ page import="javax.servlet.http.Cookie" %>
<%@ page import="org.opensaml.profile.context.ProfileRequestContext" %>
<%@ page import="net.shibboleth.idp.authn.ExternalAuthentication" %>
<%@ page import="net.shibboleth.idp.authn.context.AuthenticationContext" %>
<%@ page import="net.shibboleth.idp.profile.context.RelyingPartyContext" %>
<%@ page import="net.shibboleth.idp.ui.context.RelyingPartyUIContext" %>

<%
final Cookie[] cookies = request.getCookies();
if (cookies != null) {
    for (final Cookie cookie : cookies) {
        if (cookie.getName().equals("x509passthrough")) {
        	response.sendRedirect(request.getContextPath() + "/Authn/X509?"
                + ExternalAuthentication.CONVERSATION_KEY + "="
                + request.getParameter(ExternalAuthentication.CONVERSATION_KEY));
        	return;
        }
    }
}

final String key = ExternalAuthentication.startExternalAuthentication(request);
final ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(key, request);
final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class);
final RelyingPartyContext rpContext = prc.getSubcontext(RelyingPartyContext.class);
final RelyingPartyUIContext rpUIContext = authnContext.getSubcontext(RelyingPartyUIContext.class);
final boolean identifiedRP = rpUIContext != null && !rpContext.getRelyingPartyId().contains(rpUIContext.getServiceName());
%>
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Example Login Page</title>
    <link rel="stylesheet" type="text/css" href="<%= request.getContextPath()%>/css/main.css">
  </head>

  <body>
    <div class="wrapper">
      <div class="container">
        <header>
          <a class="logo" href="../images/dummylogo.png"><img src="<%= request.getContextPath() %>/images/dummylogo.png" alt="Replace or remove this logo"></a>
        </header>
    
        <div class="content">
          <div class="column one">
            <form id="loginform" action="<%= request.getContextPath() %>/Authn/X509" method="post">

            <input type="hidden" name="<%= ExternalAuthentication.CONVERSATION_KEY %>"
                value="<%= request.getParameter(ExternalAuthentication.CONVERSATION_KEY) %>">

              <% if (identifiedRP) { %>
                <legend>
                  Log in to <idpui:serviceName uiContext="<%= rpUIContext %>"/>
                </legend>
              <% } %>
              
              <section>
              Please make sure that your user certificate is properly configured in your web browser
              and click on the <strong>Certificate Login </strong> button.
              </section>

              <section>
                <input type="checkbox" name="x509passthrough" value="true" tabindex="2">
                Do not show this page in the future.

                <button class="form-element form-button" type="submit" name="login" value="1"
                    tabindex="1" accesskey="l">Certificate Login</button>
              </section>
            </form>

             <%
              //
              //    SP Description & Logo (optional)
              //    These idpui lines will display added information (if available
              //    in the metadata) about the Service Provider (SP) that requested
              //    authentication. These idpui lines are "active" in this example
              //    (not commented out) - this extra SP info will be displayed.
              //    Remove or comment out these lines to stop the display of the
              //    added SP information.
              //
              //    Documentation: 
              //      https://wiki.shibboleth.net/confluence/display/SHIB2/IdPAuthUserPassLoginPage
              //
              //    Example:
             %>
             <% if (identifiedRP) { %>
                 <p>
                   <idpui:serviceLogo uiContext="<%= rpUIContext %>">default</idpui:serviceLogo>
                   <idpui:serviceDescription uiContext="<%= rpUIContext %>">SP description</idpui:serviceDescription>
                 </p>
             <% } %>

          </div>
          <div class="column two">
            <ul class="list list-help">
              <li class="list-help-item"><a href="#"><span class="item-marker">&rsaquo;</span> Need Help?</a></li>
              <li class="list-help-item"><a href="https://wiki.shibboleth.net/confluence/display/SHIB2/IdPAuthUserPassLoginPage"><span class="item-marker">&rsaquo;</span> How to Customize this Skin</a></li>
            </ul>
          </div>
        </div>
      </div>

      <footer>
        <div class="container container-footer">
          <p class="footer-text">Insert your footer text here.</p>
        </div>
      </footer>
    </div>

  </body>
</html>
