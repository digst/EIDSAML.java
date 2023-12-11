<%@page import="eid.saml.session.AssertionWrapperHolder"%>
<%@page import="eid.saml.session.AssertionWrapper"%>
<!doctype html>
<html>
<head>
    <title>Secure Page</title>
</head>
<body>
<a href="../eidsaml/logout">Logout</a>
<br/>
<a href="../index.jsp">Go back to frontpage</a>

<h3>Assertion Content</h3>
<% AssertionWrapper wrapper = AssertionWrapperHolder.get(); %>

<pre>
Issuer = <%= wrapper.getIssuer() %>
PersonalIdentifier = <%= wrapper.getPersonalIdentifier() %>
Subject/NameID = <%= wrapper.getSubjectNameId() %>
AssuranceLevel = <%= wrapper.getAssuranceLevel() %>

Attributes = <%= wrapper.getAttributeValues() %>
</pre>

<h3>Assertion XML</h3>
<pre>
<%= wrapper.getAssertionAsHtml() %>
</pre>

</body>
</html>