package eid.saml;

import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectPackages( {
    "eid.saml.filter",
    "eid.saml.service",
    "eid.saml.service.validation",
    "eid.saml.servlet",
    "eid.saml.util",
    "eid.saml.audit",
    "eid.saml.session",
    "eid.saml.session.database",
    "eid.saml.session.inmenory"
})
public class TestSuite {

}
