package com.microsoftopentechnologies.acs.serialize;

import com.microsoftopentechnologies.acs.federation.AssertionCompressor;
import com.microsoftopentechnologies.acs.saml.SAMLAssertion;
import com.microsoftopentechnologies.acs.util.Utils;
import com.microsoftopentechnologies.acs.xmldsig.TrustParameters;

import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AssertionSessionSerializer extends AssertionSerializer {
    private static final Logger LOG = Logger.getLogger(AssertionSessionSerializer.class.getName());

    private static String ACS_ASSERTION_SESSION_KEY = "ACS_ASSERTION_SESSION_KEY";
    private TrustParameters trustParams;

    public AssertionSessionSerializer(TrustParameters trustParams) {
        this.trustParams = trustParams;
    }

    public SAMLAssertion getAssertion(HttpServletRequest request) throws Exception {

        SAMLAssertion assertion = null;

        try {
            String deflatedAssertionContent = (String)request.getSession().getAttribute(ACS_ASSERTION_SESSION_KEY);
            assertion = AssertionCompressor.getAssertionFromDeflatedContent(deflatedAssertionContent, trustParams.getSecretKey());
        } catch (Exception e) {
            Utils.logError("Exception occured while building SAML Assertion from the session attribute", e, LOG);
            String cause = "Session attribute content is not a valid SAML Assertion. " + e.getMessage();
            throw new Exception(cause);
        }

        logAssertion(assertion);

        return assertion;
    }

    public void saveAssertion(SAMLAssertion assertion, HttpServletRequest request, HttpServletResponse response, SecretKey secretKey) throws Exception {
        String deflatedAssertionContent = AssertionCompressor.deflateAssertionContent(assertion, secretKey);
        request.getSession().setAttribute(ACS_ASSERTION_SESSION_KEY, deflatedAssertionContent);
    }

}
