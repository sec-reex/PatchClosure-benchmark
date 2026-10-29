<%@ page contentType="text/html;charset=UTF-8" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<html><body>
<%-- Two REAL Struts UI tags. Each isolates ONE forced-OGNL attribute over the request-supplied
     action property `prop` (developer-forced via %{prop}); the other attribute is a fixed literal
     so exactly one evaluation surface is exercised per tag.

     ID-VECTOR  (S2-061 seed sink): the `id` attribute. On V0 2.5.25 setId(findString(id)) evaluates
                it once and evaluateParams(findStringIfAltSyntax) evaluates it again -> DOUBLE eval.
                On V1 2.5.26 setId no longer evaluates -> single eval -> seed BLOCKED.
     NAME-VECTOR (S2-062 residual sink): the `name` attribute. UIBean.evaluateParams re-evaluates the
                translated name via findValue -> still DOUBLE-evaluates on V1 2.5.26. On V2 2.5.30 the
                NotExcludedAcceptedPatternsChecker (isAcceptableExpression) gates the re-eval -> a
                context expression like #pcbflag is rejected -> residual BLOCKED.

     The benign #pcbflag context var (= ${PCB_FLAG}) surfaces in the rendered <input> (id or value
     attribute) IFF the version's own code performed the second OGNL evaluation. --%>
ID-VECTOR:[<s:textfield theme="simple" name="idfield" id="%{prop}"/>]
NAME-VECTOR:[<s:textfield theme="simple" id="namefield" name="%{prop}"/>]
</body></html>
