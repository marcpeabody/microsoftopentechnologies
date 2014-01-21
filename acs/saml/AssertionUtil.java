package com.microsoftopentechnologies.acs.saml;

import com.microsoftopentechnologies.acs.util.Utils;

import java.util.logging.Logger;

public class AssertionUtil {
    private static final Logger LOG = Logger.getLogger(AssertionUtil.class.getName());

    public static String getUserFromAssertion(SAMLAssertion assertion) {
        String user = null;
        // Check name claim attribute. If exists set as remote user else use NameID
        SAMLAssertion.Attribute[] attributes = assertion.getAttributes();
        for (SAMLAssertion.Attribute attribute : attributes) {
            if (attribute.getName().endsWith("claims/name")) {
                user = attribute.getValues()[0];
                break;
            }
        }

        if (user == null) {
            Utils.logDebug("No name claim found in the assertion, so assuming subject's name identifier as the remote user.", LOG);
            user = assertion.getSubject().getNameIdentifier();
        }
        return user;
    }

    public static String getSubdomainFromAssertion(SAMLAssertion assertion) {
        String subdomain = null;
        // Check name claim attribute. If exists set as subdomain
        SAMLAssertion.Attribute[] attributes = assertion.getAttributes();
        for (SAMLAssertion.Attribute attribute : attributes) {
            if (attribute.getName().endsWith("subdomain")) {
                subdomain = attribute.getValues()[0];
                break;
            }
        }

        return subdomain;
    }
}
