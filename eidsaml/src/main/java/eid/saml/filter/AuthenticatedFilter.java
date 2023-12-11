package eid.saml.filter;

import java.io.IOException;
import java.util.*;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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

public class AuthenticatedFilter implements Filter {
    private static final Logger log = LoggerFactory.getLogger(AuthenticatedFilter.class);
    private boolean isPassive, forceAuthn;
    private String attributeProfile;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        HashMap<String, String> config = getConfig(filterConfig);
        
        String isPassiveStr = config.get(Constants.IS_PASSIVE);
        String isForceAuthnStr = config.get(Constants.FORCE_AUTHN);

        isPassive = (isPassiveStr != null) ? Boolean.parseBoolean(isPassiveStr) : false;
        forceAuthn = (isForceAuthnStr != null) ? Boolean.parseBoolean(isForceAuthnStr) : false;

        if (isPassive && forceAuthn) {
            log.warn("IsPassive and forceAuthn Cannot both be true");
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        
        log.debug("AuthenticatedFilter invoked by endpoint: '{}{}'", req.getContextPath(), req.getServletPath());

        try {
            EIDSAMLService.getSessionCleanerService().startCleanerIfMissing(req.getSession());
            SessionHandler sessionHandler = EIDSAMLService.getSessionHandlerFactory().getHandler();
            AssertionWrapper assertionWrapper = sessionHandler.getAssertion(req.getSession());

            // Is the user authenticated, and at the required level?
            if (userNeedsAuthentication(req, sessionHandler, assertionWrapper)) {
                log.debug("Filter config: isPassive: {}, forceAuthn: {}", isPassive, forceAuthn);

                AuthnRequestService authnRequestService = AuthnRequestService.getInstance();

                String requestPath = req.getRequestURI();
                if(req.getQueryString() != null) {
                    requestPath += "?" + req.getQueryString();
                }

                MessageContext<SAMLObject> authnRequest = authnRequestService.createMessageWithAuthnRequest(isPassive, forceAuthn, attributeProfile);

                //Audit logging
                EIDSAMLService.getAuditService().auditLog(AuditRequestUtil
                        .createBasicAuditBuilder(req, "BSA1", "AuthnRequest")
                        .withAuthnAttribute("AUTHN_REQUEST_ID", ((AuthnRequest)authnRequest.getMessage()).getID())
                        .withAuthnAttribute("URL", requestPath));

                sendAuthnRequest(req, res, authnRequest, requestPath);
            }
            else {
                try {
                    putAssertionOnThreadLocal(req.getSession());

                    // User already authenticated to the correct level
                    chain.doFilter(req, res);
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

    @Override
    public void destroy() {
        EIDSAMLService.getSessionCleanerService().stopCleaner();
        EIDSAMLService.getSessionHandlerFactory().close();
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
