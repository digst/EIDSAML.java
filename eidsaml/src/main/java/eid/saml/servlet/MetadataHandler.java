package eid.saml.servlet;

import eid.saml.service.SPMetadataService;
import eid.saml.util.InternalException;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.core.config.InitializationException;

public class MetadataHandler extends SAMLHandler {

    @Override
    public void handleGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, InitializationException, InternalException {
        httpServletResponse.setContentType("application/xml");
        httpServletResponse.getWriter().print(SPMetadataService.getInstance().getMarshalledMetadata());
    }

    @Override
    public void handlePost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        throw new UnsupportedOperationException("POST not allowed");
    }
}
