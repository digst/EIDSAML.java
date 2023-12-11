package eid.saml.session;

import eid.saml.config.Configuration;
import eid.saml.service.EIDSAMLService;
import eid.saml.util.TestConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;

class SessionDestroyListenerTest {

    @BeforeEach
    void beforeEach() throws Exception {
        Configuration configuration = new Configuration.Builder()
                .setSpEntityID(TestConstants.SP_ENTITY_ID)
                .setBaseUrl(TestConstants.SP_BASE_URL)
                .setServletRoutingPathPrefix(TestConstants.SP_ROUTING_BASE)
                .setServletRoutingPathSuffixError(TestConstants.SP_ROUTING_ERROR)
                .setServletRoutingPathSuffixMetadata(TestConstants.SP_ROUTING_METADATA)
                .setServletRoutingPathSuffixLogout(TestConstants.SP_ROUTING_LOGOUT)
                .setServletRoutingPathSuffixLogoutResponse(TestConstants.SP_ROUTING_LOGOUT_RESPONSE)
                .setServletRoutingPathSuffixAssertion(TestConstants.SP_ROUTING_ASSERTION)
                .setIdpEntityID(TestConstants.IDP_ENTITY_ID)
                .setIdpMetadataUrl(TestConstants.IDP_METADATA_URL)
                .setSessionHandlerFactoryClassName(TestSessionHandlerFactory.class.getName())
                .setKeystoreLocation("sp.pfx")
                .setKeystorePassword("Test1234")
                .setKeyAlias("1")
                .build();

        EIDSAMLService.init(configuration);

    }

    @DisplayName("Test that current session is logged out after execution")
    @Test
    void testLogoutCurrentSession() throws Exception {
        SessionDestroyListener sessionDestroyListener = new SessionDestroyListener();

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        HttpSessionEvent httpSessionEvent = Mockito.mock(HttpSessionEvent.class);
        Mockito.when(httpSessionEvent.getSession()).thenReturn(session);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);

        SessionHandler sessionHandler = EIDSAMLService.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        sessionDestroyListener.sessionCreated(httpSessionEvent);

        sessionDestroyListener.sessionDestroyed(httpSessionEvent);

        Mockito.verify(sessionHandler,Mockito.times(1)).logout(session,assertionWrapper);
    }

    @DisplayName("Test that session is ignored if not logged in")
    @Test
    void testIgnoreMissingSession() throws Exception {
        SessionDestroyListener sessionDestroyListener = new SessionDestroyListener();

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        HttpSessionEvent httpSessionEvent = Mockito.mock(HttpSessionEvent.class);
        Mockito.when(httpSessionEvent.getSession()).thenReturn(session);

        SessionHandler sessionHandler = EIDSAMLService.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        sessionDestroyListener.sessionCreated(httpSessionEvent);

        sessionDestroyListener.sessionDestroyed(httpSessionEvent);

        Mockito.verify(sessionHandler,Mockito.never()).logout(Mockito.any(HttpSession.class),Mockito.any(AssertionWrapper.class));
    }
}