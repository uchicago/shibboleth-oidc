<%--

    Licensed to the University Corporation for Advanced Internet Development,
    Inc. (UCAID) under one or more contributor license agreements.  See the
    NOTICE file distributed with this work for additional information regarding
    copyright ownership. The UCAID licenses this file to You under the Apache
    License, Version 2.0 (the "License"); you may not use this file except in
    compliance with the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

--%>
<%
final org.springframework.web.context.WebApplicationContext springContext =
    org.springframework.web.context.support.WebApplicationContextUtils.getRequiredWebApplicationContext(request.getServletContext());
final String path = springContext.getEnvironment().getProperty("idp.home") + "/metadata/idp-metadata.xml";
try (final java.io.FileInputStream in = new java.io.FileInputStream(path)) {
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