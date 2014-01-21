package com.microsoftopentechnologies.acs.serialize;

import com.microsoftopentechnologies.acs.saml.SAMLAssertion;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;


public abstract class AssertionSerializer {
    private static final Logger LOG = Logger.getLogger(AssertionSerializer.class.getName());

    public abstract SAMLAssertion getAssertion(HttpServletRequest request) throws Exception;
    public abstract void saveAssertion(SAMLAssertion assertion, HttpServletRequest request, HttpServletResponse httpResponse, SecretKey secretKey) throws Exception;


    protected void logAssertion(SAMLAssertion assertion) {
        LOG.log(Level.FINE, "Locally restored Assertion attibutes: ");
        for (SAMLAssertion.Attribute attribute : assertion.getAttributes()) {
            LOG.log(Level.FINE,attribute.getName() + ":" + Arrays.toString(attribute.getValues()));
        }
    }
}
