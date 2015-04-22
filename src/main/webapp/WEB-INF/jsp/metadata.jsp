<%
    final org.springframework.web.context.WebApplicationContext springContext =
            org.springframework.web.context.support.WebApplicationContextUtils.getRequiredWebApplicationContext(request.getServletContext());
    final ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    final java.net.URL resource = classLoader.getResource("/metadata/idp-metadata.xml");
    java.io.File file = new java.io.File(resource.toURI());

    try (final java.io.FileInputStream in = new java.io.FileInputStream(file)) {
        int i;
        while ((i = in.read()) != -1) {
            out.write(i);
        }
    } catch (final java.io.IOException e) {
        out.println(e.getMessage());
        return;
    }

    final String acceptHeader = request.getHeader("Accept");
    if (acceptHeader != null && !acceptHeader.contains("application/samlmetadata+xml")) {
        response.setContentType("application/xml");
    } else {
        response.setContentType("application/samlmetadata+xml");
    }

%>
