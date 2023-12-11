package eid.saml.service;

import eid.saml.audit.AuditService;
import eid.saml.session.InternalSessionHandlerFactory;
import eid.saml.session.SessionCleanerService;
import eid.saml.session.SessionHandlerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;

import eid.saml.config.Configuration;

public class EIDSAMLService {
    private static final Logger log = LoggerFactory.getLogger(EIDSAMLService.class);

    public static boolean initialized = false;
    private static Configuration configuration;
    private static AuditService auditService;
    private static CredentialService credentialService;
    private static SessionHandlerFactory sessionHandlerFactory;
    private static SessionCleanerService sessionCleanerService;

    public static void init(Configuration configuration) throws InitializationException {
        log.debug("Initializing EIDSAML");
        initialized = false;

        try {
            // Validate Crypto
            log.debug("Validating Java Cryptographic Architecture");
            JavaCryptoValidationInitializer cryptoValidationInitializer = new JavaCryptoValidationInitializer();
            cryptoValidationInitializer.init();

            // Initialize OpenSAML
            log.debug("Initializing OpenSAML");
            InitializationService.initialize();

            // Set configuration
            log.debug("Setting EIDSAML Configuration");
            EIDSAMLService.configuration = configuration;
            EIDSAMLService.auditService = new AuditService(configuration);
            EIDSAMLService.credentialService = new CredentialService(configuration);
            EIDSAMLService.sessionCleanerService = new SessionCleanerService(configuration);
            EIDSAMLService.sessionHandlerFactory = new InternalSessionHandlerFactory();
            EIDSAMLService.sessionHandlerFactory.configure(configuration);

            initialized = true;
        } catch (Exception exception) {
            log.error("Unable to initialize EIDSAML",exception);
            throw new InitializationException(String.format("Unable to initialize EIDSAML '%s'", exception.getMessage()), exception);
        }
        log.debug("EIDSAML Initialized");
    }

    public static Configuration getConfig() throws RuntimeException {
        ifNotInitializedThrowRuntimeException("Configuration");
        return configuration;
    }

    public static AuditService getAuditService() throws RuntimeException {
        ifNotInitializedThrowRuntimeException("AuditService");
        return auditService;
    }

    public static SessionHandlerFactory getSessionHandlerFactory() throws RuntimeException {
        ifNotInitializedThrowRuntimeException("SessionHandlerFactory");
        return sessionHandlerFactory;
    }

    public static SessionCleanerService getSessionCleanerService() {
        ifNotInitializedThrowRuntimeException("SessionCleanerService");
        return sessionCleanerService;
    }

    public static CredentialService getCredentialService() {
        ifNotInitializedThrowRuntimeException("CredentialService");
        return credentialService;
    }

    private static void ifNotInitializedThrowRuntimeException(String entity) {
        if (!initialized) {
            throw new RuntimeException(String.format("EIDSAML is uninitialized, '%s' is unavailable", entity));
        }
    }
}
