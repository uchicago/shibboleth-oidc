<%@ page pageEncoding="UTF-8" %>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title><spring:message code="${root.title}" text="Shibboleth IdP" /></title>
    <link rel="stylesheet" type="text/css" href="<%= request.getContextPath()%>/css/main.css">
  </head>

  <body>
    <div class="wrapper">
      <div class="container">
        <header>
          <a class="logo" href="../images/dummylogo.png"><img src="<%= request.getContextPath() %>/images/dummylogo.png" alt="Replace or remove this logo"></a>
        </header>
    
        <div class="content">
          <h2><spring:message code="${root.message}" text="No services are available at this location." /></h2>
        </div>
      </div>

      <footer>
        <div class="container container-footer">
          <p><spring:message code="${root.footer}" text="Insert your footer text here." /></p>
        </div>
      </footer>
    </div>

  </body>
</html>
