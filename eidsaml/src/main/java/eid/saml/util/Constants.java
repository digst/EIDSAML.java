package eid.saml.util;

public class Constants {

    // Session constants
    public static final String SESSION_ERROR_TYPE = "eidsaml.error.type";
    public static final String SESSION_ERROR_MESSAGE = "eidsaml.error.message";

    // Configuration constants for DispatcherServlet (required)
    public static final String SP_ENTITY_ID = "eidsaml.servlet.entityid";
    public static final String SP_BASE_URL = "eidsaml.servlet.baseurl";
    public static final String KEYSTORE_LOCATION = "eidsaml.servlet.keystore.location";
    public static final String KEYSTORE_PASSWORD = "eidsaml.servlet.keystore.password";
    public static final String KEY_ALIAS = "eidsaml.servlet.keystore.alias";
    public static final String IDP_ENTITY_ID = "eidsaml.servlet.idp.entityid";
    public static final String IDP_METADATA_FILE = "eidsaml.servlet.idp.metadata.file";
    public static final String IDP_METADATA_URL = "eidsaml.servlet.idp.metadata.url";

    // Configuration constants for DispatcherServlet (optional, has default values)
    public static final String EXTERNAL_CONFIGURATION_FILE = "eidsaml.servlet.configurationfile";
    public static final String EIDSAML_VALIDATION_ENABLED = "eidsaml.servlet.profile.validation.enabled";
    public static final String EIDSAML_ASSURANCE_LEVEL_SKIP = "eidsaml.servlet.profile.validation.assurancelevel.skip";
    public static final String EIDSAML_ASSURANCE_LEVEL_MINIMUM = "eidsaml.servlet.profile.validation.assurancelevel.minimum";
    public static final String METADATA_NAMEID_FORMAT = "eidsaml.servlet.metadata.nameid.format";
    public static final String METADATA_CONTACT_EMAIL = "eidsaml.servlet.metadata.contact.email";
    public static final String METADATA_CONTACT_COMPANY = "eidsaml.servlet.metadata.contact.company";
    public static final String METADATA_CONTACT_GIVEN_NAME = "eidsaml.servlet.metadata.contact.given.name";
    public static final String METADATA_CONTACT_SURNAME = "eidsaml.servlet.metadata.contact.surname";
    public static final String METADATA_CONTACT_TELEPHONE_NUMBER = "eidsaml.servlet.metadata.contact.telephone.number";
    public static final String IDP_METADATA_MIN_REFRESH = "eidsaml.servlet.idp.metadata.refresh.min";
    public static final String IDP_METADATA_MAX_REFRESH = "eidsaml.servlet.idp.metadata.refresh.max";
    public static final String SECONDARY_KEYSTORE_LOCATION = "eidsaml.servlet.secondary.keystore.location";
    public static final String SECONDARY_KEYSTORE_PASSWORD = "eidsaml.servlet.secondary.keystore.password";
    public static final String SECONDARY_KEY_ALIAS = "eidsaml.servlet.secondary.keystore.alias";
    public static final String SIGNATURE_ALGORITHM = "eidsaml.servlet.signature.algorithm";
    public static final String ERROR_PAGE = "eidsaml.servlet.secondary.page.error";
    public static final String LOGOUT_PAGE = "eidsaml.servlet.secondary.page.logout";
    public static final String LOGIN_PAGE = "eidsaml.servlet.secondary.page.login";
    public static final String SUPPORT_SELF_SIGNED = "eidsaml.servlet.trust.selfsigned.certs";
    public static final String SP_ROUTING_BASE = "eidsaml.servlet.routing.path.prefix";
    public static final String SP_ROUTING_ERROR = "eidsaml.servlet.routing.path.suffix.error";
    public static final String SP_ROUTING_METADATA = "eidsaml.servlet.routing.path.suffix.metadata";
    public static final String SP_ROUTING_LOGOUT = "eidsaml.servlet.routing.path.suffix.logout";
    public static final String SP_ROUTING_LOGOUT_RESPONSE = "eidsaml.servlet.routing.path.suffix.logoutResponse";
    public static final String SP_ROUTING_ASSERTION = "eidsaml.servlet.routing.path.suffix.assertion";
    public static final String SP_AUDIT_CLASSNAME = "eidsaml.servlet.audit.logger.classname";
    public static final String SP_AUDIT_ATTRIBUTE_IP = "eidsaml.servlet.audit.logger.attribute.ip";
    public static final String SP_AUDIT_ATTRIBUTE_PORT = "eidsaml.servlet.audit.logger.attribute.port";
    public static final String SP_AUDIT_ATTRIBUTE_USER_ID = "eidsaml.servlet.audit.logger.attribute.userid";
    public static final String SP_AUDIT_ATTRIBUTE_SESSION_ID = "eidsaml.servlet.audit.logger.attribute.sessionId";
    public static final String SP_SESSION_HANDLER_FACTORY_CLASSNAME ="eidsaml.servlet.session.handler.factory";
    public static final String SP_SESSION_HANDLER_JNDI_NAME ="eidsaml.servlet.session.handler.jdni.name";
    public static final String SP_SESSION_HANDLER_JDBC_URL = "eidsaml.servlet.session.handler.jdbc.url";
    public static final String SP_SESSION_HANDLER_JDBC_USERNAME = "eidsaml.servlet.session.handler.jdbc.username";
    public static final String SP_SESSION_HANDLER_JDBC_PASSWORD = "eidsaml.servlet.session.handler.jdbc.password";
    public static final String SP_SESSION_HANDLER_JDBC_DRIVER_CLASSNAME = "eidsaml.servlet.session.handler.jdbc.driver.classname";
    public static final String SP_SESSION_HANDLER_MAX_NUM_TRACKED_ASSERTIONIDS ="eidsaml.servlet.session.handler.inmemory.max.tracked.assertionids";

    // Configuration constants for revocation check settings
    public static final String CRL_CHECK_ENABLED = "eidsaml.servlet.revocation.crl.check.enabled";
    public static final String OCSP_CHECK_ENABLED = "eidsaml.servlet.revocation.ocsp.check.enabled";

    // Configuration constants for AuthenticationFilter
    public static final String IS_PASSIVE = "eidsaml.filter.ispassive.enabled";
    public static final String FORCE_AUTHN = "eidsaml.filter.forceauthn.enabled";
    public static final String REQUIRED_NSIS_LEVEL = "eidsaml.filter.nsis.required";

    // SAML Attributes constants
    public static final String SPEC_VER = "https://data.gov.dk/model/core/specVersion";
    public static final String LOA = "http://eidas.europa.eu/LoA";
    public static final String ORGANIZATION_NAME = "https://data.gov.dk/model/core/eid/professional/orgName";
    public static final String ASSURANCE_LEVEL = "dk:gov:saml:attribute:AssuranceLevel";

    public static final String EIDAS_ATTRIBUTE_NATURAL_PERSONIDENTIFIER = "dk:gov:saml:attribute:eidas:naturalperson:PersonIdentifier";
}
