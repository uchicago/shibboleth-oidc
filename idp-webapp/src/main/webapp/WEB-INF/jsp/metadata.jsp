<%
final org.springframework.web.context.WebApplicationContext springContext =
    org.springframework.web.context.support.WebApplicationContextUtils.getRequiredWebApplicationContext(request.getServletContext());
final String path = springContext.getEnvironment().getProperty("idp.home") + "/metadata/idp-metadata.xml";
final String showMetadata = springContext.getEnvironment().getProperty("idp.entityID.url.enable", "true");

if (null != showMetadata && !Boolean.valueOf(showMetadata.trim())) {
   response.sendError(404);
} else {
   java.io.InputStreamReader in = null;
   try {
      in = new java.io.InputStreamReader(new java.io.FileInputStream(path),"UTF8");
      int i;
      while ((i = in.read()) != -1) {
         out.write(i);
      }
   } catch (final java.io.IOException e) {
      out.println(e.getMessage());
      return;
   } finally {
      if (null != in) {
         try {
            in.close();
         } catch (java.io.IOException e) {
         }
      }
   }

   final String acceptHeader = request.getHeader("Accept");
   if (acceptHeader != null && !acceptHeader.contains("application/samlmetadata+xml")) {
      response.setContentType("application/xml");
   } else {
      response.setContentType("application/samlmetadata+xml");
   }
}
%>