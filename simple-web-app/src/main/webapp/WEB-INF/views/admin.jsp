<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<o:header title="Admin"/>
<o:topbar pageName="Admin"/>
<div class="container-fluid main">
	<div class="row-fluid">
		<div class="span10 offset1">

			<h1>Hello ${ userInfo.name }</h1>

			<div>
				<p>This page requires that the user be logged in with a valid account and the <code>ROLE_ADMIN</code> Spring Security authority.
				If you are reading this page, <span class="text-success">you are currently logged in as an administrator</span>.</p>

				<p>The authorization provider will assign your account a set of authorities depending on how it's configured.
				Your current login has the following Spring Security authorities:</p>
				
				<ul>
					<security:authentication property="authorities" var="authorities" />
					<c:forEach items="${authorities}" var="auth">
						<li><code>${ auth }</code></li>
					</c:forEach>
				</ul>
				
			</div>
			<div>
				<h3>Administrators</h3>
				
				<p>Logged in users are assigned the <code>ROLE_USER</code> authority by default, but the following users
				 (identified by issuer/subject pairs) will also be given <code>ROLE_ADMIN</code>:</p>
				
				<table class="table table-striped table-hover span4">
					<tr>
						<th>Issuer</th>
						<th>Subject</th>
					</tr>
					<c:forEach items="${ admins }" var="admin">
						<tr>
							<td>${ admin.issuer }</td>
							<td>${ admin.subject }</td>
						</tr>
					</c:forEach>
				</table>
			</div>

		</div>
	</div>
</div>


<o:footer />
