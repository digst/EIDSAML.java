package eid.saml.service;

import eid.saml.config.Configuration;
import eid.saml.session.TestSessionHandlerFactory;
import eid.saml.util.InternalException;
import eid.saml.util.TestConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;

class EIDSAMLServiceTest {

    @DisplayName("Test that initialization fail if unable to open keystore")
    @Test
    void testInvalidKeystoreConfiguration() throws InternalException, InitializationException {
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
                .setKeystoreLocation(TestConstants.SP_KEYSTORE_LOCATION)
                .setKeystorePassword(TestConstants.SP_KEYSTORE_PASSWORD)
                .setKeyAlias("Invalid alias")
                .build();

        Exception initializationException = Assertions.assertThrows(InitializationException.class , () -> {
            EIDSAMLService.init(configuration);
        });
        Assertions.assertEquals(initializationException.getMessage(), "Unable to initialize EIDSAML 'Malformed configuration in 'eidsaml.servlet.keystore' or keystore file'");

        Exception exception = Assertions.assertThrows(RuntimeException.class , () -> {
            EIDSAMLService.getCredentialService();
        });
        Assertions.assertEquals(exception.getMessage(), "EIDSAML is uninitialized, 'CredentialService' is unavailable");
    }

    @DisplayName("Test that services are initialized with valid configuration")
    @Test
    void testValidConfiguration() throws InternalException, InitializationException {
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
                .setKeystoreLocation(TestConstants.SP_KEYSTORE_LOCATION)
                .setKeystorePassword(TestConstants.SP_KEYSTORE_PASSWORD)
                .setKeyAlias(TestConstants.SP_KEYSTORE_ALIAS)
                .build();

        EIDSAMLService.init(configuration);

        Assertions.assertEquals(configuration, EIDSAMLService.getConfig());
        Assertions.assertNotNull(EIDSAMLService.getAuditService());
        Assertions.assertNotNull(EIDSAMLService.getCredentialService());
        Assertions.assertNotNull(EIDSAMLService.getSessionCleanerService());
        Assertions.assertNotNull(EIDSAMLService.getSessionHandlerFactory().getHandler());
    }
}