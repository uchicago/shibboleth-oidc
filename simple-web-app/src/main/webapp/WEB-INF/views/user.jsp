<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<o:header title="User"/>
<o:topbar pageName="User"/>
<div class="container-fluid main">
	<div class="row-fluid">
		<div class="span10 offset1">

			<h1>Hello ${ userInfo.name }</h1>

			<div>
				<p>This page requires that the user be logged in with a valid account and the <code>ROLE_USER</code> Spring Security authority.
				If you are reading this page, <span class="text-success">you are currently logged in</span>.</p>
				
				<security:authentication var="user" property="principal" />
				
				<p>The authorization provider will create a Principal object based on the <code>iss</code> and <code>sub</code>
				claims associated with your ID token. This value can be used as a globally unique username within the application
				(though it's not meant to be human-readable).
				Your Principal is: <code>${ user }</code></p>

				<p>The authorization provider will assign your account a set of authorities depending on how it's configured.
				Your current login has the following Spring Security authorities:</p>
				
				<ul>
					<security:authentication property="authorities" var="authorities" />
					<c:forEach items="${authorities}" var="auth">
						<li><code>${ auth }</code></li>
					</c:forEach>
				</ul>
				
				<h3>ID Token</h3>

				<p>Your ID Token has the following set of claims:</p>
				
				<security:authentication property="idTokenValue" var="idToken" />
				<table class="table table-striped table-hover" id="idTokenTable">
					<thead>
						<tr>
							<th>Name</th>
							<th>Value</th>
						</tr>
					</thead>
					<tbody>
					</tbody>				
				</table>

				<h3>User Info</h3>
				
				<p>The call to the User Info Endpoint returned the following set of claims:</p>

				<table class="table table-striped table-hover" id="userInfoTable">
					<thead>
						<tr>
							<th>Name</th>
							<th>Value</th>
						</tr>
					</thead>
					<tbody>
					</tbody>				
				</table>

			</div>

		</div>
	</div>
</div>

<script type="text/javascript">
	$(document).ready(function () {

		var idTokenString = "${ idToken }";
		var idToken = jwt.WebTokenParser.parse(idTokenString);
		var idClaims = JSON.parse(jwt.base64urldecode(idToken.payloadSegment));
	
		_.each(idClaims, function(val, key, list) {
			$('#idTokenTable tbody').append('<tr><td>' + _.escape(key) + '</td><td>' + _.escape(val) + '</td></tr>');
		});

		var userInfo = ${ userInfoJson };
		_.each(userInfo, function(val, key, list) {
		    if(key === "address" && 'formatted' in val) {
		        address = JSON.parse(val.formatted);
                if('formatted' in address) {
			        $('#userInfoTable tbody').append('<tr><td>' + _.escape(key) + '</td><td>' + address.formatted + '</td></tr>');
                }
		    } else {
			    $('#userInfoTable tbody').append('<tr><td>' + _.escape(key) + '</td><td>' + _.escape(val) + '</td></tr>');
		    }
		});
	});

</script>

<o:footer />