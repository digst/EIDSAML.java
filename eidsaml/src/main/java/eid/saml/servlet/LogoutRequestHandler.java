package eid.saml.servlet;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eid.saml.session.SessionHandler;
import eid.saml.util.*;
import eid.saml.config.Configuration;
import eid.saml.service.EIDSAMLService;

public class LogoutRequestHandler extends SAMLHandler {
    private static final Logger log = LoggerFactory.getLogger(LogoutRequestHandler.class);

    @Override
    public void handleGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ExternalException, InternalException, IOException {
        log.debug("Handling HTTP LogoutRequest");
        handleServiceProviderRequest( httpServletRequest,  httpServletResponse);
    }

    @Override
    public void handlePost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ExternalException, InternalException, IOException {
        handleGet(httpServletRequest, httpServletResponse);
    }

    @Override
    public void handleSOAP(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ExternalException, InternalException, IOException {
        log.debug("Handling SOAP LogoutRequest");
        handleGet(httpServletRequest, httpServletResponse);
    }

    private void handleServiceProviderRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ExternalException, InternalException {
        log.debug("Handling ServiceProvider LogoutRequest");
        SessionHandler sessionHandler = EIDSAMLService.getSessionHandlerFactory().getHandler();
        boolean authenticated = sessionHandler.isAuthenticated(httpServletRequest.getSession());

        log.debug("Authenticated: {}", authenticated);

        // forward to logout redirect page
        Configuration config = EIDSAMLService.getConfig();
        String url = StringUtil.getUrl(httpServletRequest, config.getLogoutPage());

        // Invalidate current http session - remove all data
        httpServletRequest.getSession().invalidate();

        // finish up since no session is maintained in the eid gateway side
        log.warn("User not logged in, redirecting to " + url);
        httpServletResponse.sendRedirect(url);
        return;
    }
}
