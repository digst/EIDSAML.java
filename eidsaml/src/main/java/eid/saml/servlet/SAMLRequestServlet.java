package eid.saml.servlet;

import java.io.IOException;
import java.util.*;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServlet;

import eid.saml.config.Configuration;
import eid.saml.service.EIDSAMLService;
import eid.saml.session.*;
import eid.saml.util.*;
import org.opensaml.core.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;

import eid.saml.service.AuthnRequestService;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

public class SAMLRequestServlet extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(SAMLRequestServlet.class);
    private String attributeProfile;

    public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException
    {
        log.debug("AuthenticatedFilter invoked by endpoint: '{}{}'", request.getContextPath(), request.getServletPath());

        try {
            request.getSession(true);
            EIDSAMLService.getSessionCleanerService().startCleanerIfMissing(request.getSession());
            SessionHandler sessionHandler = EIDSAMLService.getSessionHandlerFactory().getHandler();
            AssertionWrapper assertionWrapper = sessionHandler.getAssertion(request.getSession());

            // Is the user authenticated, and at the required level?
            if (userNeedsAuthentication(request, sessionHandler, assertionWrapper)) {
                log.debug("Filter config: isPassive: {}, forceAuthn: {}", false, true);

                AuthnRequestService authnRequestService = AuthnRequestService.getInstance();

                String requestPath = request.getRequestURI();
                if(request.getQueryString() != null) {
                    requestPath += "?" + request.getQueryString();
                }

                MessageContext<SAMLObject> authnRequest = authnRequestService.createMessageWithAuthnRequest(false, true, attributeProfile);

                //Audit logging
                EIDSAMLService.getAuditService().auditLog(AuditRequestUtil
                        .createBasicAuditBuilder(request, "BSA1", "AuthnRequest")
                        .withAuthnAttribute("AUTHN_REQUEST_ID", ((AuthnRequest)authnRequest.getMessage()).getID())
                        .withAuthnAttribute("URL", requestPath));

                sendAuthnRequest(request, response, authnRequest, requestPath);
            }
            else {
                try {
                    putAssertionOnThreadLocal(request.getSession());
                }
                finally {
                    removeAssertionFromThreadLocal();
                }
            }
        }
        catch (Exception e) {
            log.warn("Unexpected error in authentication filter", e);

            throw new ServletException(e);
        }
    }

    private boolean userNeedsAuthentication(HttpServletRequest req, SessionHandler sessionHandler, AssertionWrapper assertionWrapper) {
        if (null == assertionWrapper || !sessionHandler.isAuthenticated(req.getSession())) {
            log.debug("Unauthenticated session");
            return true;
        }
        log.debug("Authenticated session");
        return false;
    }

    private void removeAssertionFromThreadLocal() {
        AssertionWrapperHolder.clear();
    }

    private void putAssertionOnThreadLocal(HttpSession session) throws InternalException {
        SessionHandler sessionHandler = EIDSAMLService.getSessionHandlerFactory().getHandler();
        AssertionWrapper assertion = sessionHandler.getAssertion(session);
        if (assertion != null) {
            AssertionWrapperHolder.set(assertion);

            if (log.isDebugEnabled()) {
                log.debug("Saved Wrapped Assertion to ThreadLocal");
            }
        }
        else {
            log.warn("No assertion available on session");
        }
    }

    private void sendAuthnRequest(HttpServletRequest req, HttpServletResponse res, MessageContext<SAMLObject> authnRequest, String requestPath) throws InternalException {
        try {
            log.debug("AuthnRequest: {}", StringUtil.elementToString(SamlHelper.marshallObject(authnRequest.getMessage())));
        }
        catch (MarshallingException e) {
            log.warn("Could not marshall AuthnRequest for logging purposes");
        }

        // Save authnRequest on session
        SessionHandler sessionHandler = EIDSAMLService.getSessionHandlerFactory().getHandler();
        AuthnRequestWrapper wrapper = new AuthnRequestWrapper((AuthnRequest) authnRequest.getMessage(), requestPath);

        sessionHandler.storeAuthnRequest(req.getSession(), wrapper);

        log.info("Outgoing AuthnRequest - ID:'{}' Issuer:'{}' IssueInstant:'{}' Destination:'{}'", wrapper.getId(), wrapper.getIssuer(), wrapper.getIssueInstant(), wrapper.getDestination());

        // Deflating and sending the message
        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        encoder.setMessageContext(authnRequest);
        encoder.setHttpServletResponse(res);

        try {
            EIDSAMLService.getAuditService().auditLog(AuditRequestUtil
                    .createBasicAuditBuilder(req, "BSA2", "SendAuthnRequest")
                    .withAuthnAttribute("AUTHN_REQUEST_ID", ((AuthnRequest)authnRequest.getMessage()).getID()));

            encoder.initialize();
            encoder.encode();
        }
        catch (ComponentInitializationException | MessageEncodingException e) {
            throw new InternalException("Failed sending AuthnRequest", e);
        }
    }

    private HashMap<String, String> getConfig(FilterConfig filterConfig) {
        HashMap<String, String> configMap = new HashMap<>();
        Enumeration<String> keys = filterConfig.getInitParameterNames();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            String value = filterConfig.getInitParameter(key);
            configMap.put(key, value);
        }

        return configMap;
    }
}