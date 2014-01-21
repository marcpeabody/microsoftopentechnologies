/*
 Copyright 2013 Microsoft Open Technologies, Inc. 

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */
package com.microsoftopentechnologies.acs.federation;

import com.microsoftopentechnologies.acs.saml.AssertionUtil;
import com.microsoftopentechnologies.acs.saml.InvalidAssertionException;
import com.microsoftopentechnologies.acs.saml.SAMLAssertion;
import com.microsoftopentechnologies.acs.util.Utils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ACSFilterCommand {
	private static final Logger LOG = Logger.getLogger(ACSFilterCommand.class.getName());

    public static final String ACS_SAML = "ACSSAML";
    public static final String ACS_SUBDOMAIN = "ACS_SUBDOMAIN";

    private final ACSConfigurationHelper config;
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final FilterChain chain;

	public ACSFilterCommand(ACSConfigurationHelper configuration, HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
        this.config = configuration;
        this.request = request;
        this.response = response;
        this.chain = chain;
	}

    public void execute() throws IOException, ServletException, LogonFailureException {
        if (isThisRequestAResponseFromACS()) {
            handleTheResponseFromACS();
        } else {
            handleUserInboundRequest();
        }
    }

    private boolean isThisRequestAResponseFromACS() {
        // Check if this an ACS redirect by looking for a POST request with wresult and wctx parameters
        if (request.getMethod().equalsIgnoreCase("POST")) {
            String wresult = request.getParameter("wresult");
            String wctx = request.getParameter("wctx");
            if (wresult != null && wctx != null) {
                return true;
            }
        }
        return false;
    }

    private void handleTheResponseFromACS() throws LogonFailureException {
        try {
            SAMLAssertion assertion = getSAMLAssertionFromACSResponse();

            // Validate assertion
            assertion.checkAssertionValidity(config.trustParams, true);
            checkHttpValidity();

            config.getAssertionSerializer().saveAssertion(assertion, request, response, config.trustParams.getSecretKey());

            authenticationSuccessfulRedirect();

        } catch (LogonFailureException lfe) {
            throw lfe;
        } catch (InvalidAssertionException e) {
            throw new LogonFailureException("SAML assertion not valid.");
        }catch (Exception e) {
            throw new LogonFailureException("Error occured while processing SAML assertion");
        }
    }

    private void handleUserInboundRequest() throws IOException {
        try {
            // look for assertion - an exception is thrown if anything goes wrong
            SAMLAssertion validAssertion = config.getAssertionSerializer().getAssertion(request);
            invokeChainWithRemoteUser(validAssertion);
        } catch (Exception e) {
            // user is not properly authenticated, so send them to ACS for authentication
            redirectToACS();
        }
    }

    private void logAssertionAttributes(SAMLAssertion assertion) {
        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "Assertion attibutes :");
            for (SAMLAssertion.Attribute attribute : assertion.getAttributes()) {
                LOG.log(Level.FINE, attribute.getName() + ":" + Arrays.toString(attribute.getValues()));
            }
        }
    }

    private void checkHttpValidity() throws LogonFailureException {
        if(!request.isSecure() && !config.trustParams.getAllowHttp()) {
            throw new LogonFailureException("Cannot process the request over unsecured protocols.");
        }
    }

    private void authenticationSuccessfulRedirect() throws IOException {
        String wctx = request.getParameter("wctx");
        /*
         *  Authenticated. Now redirect to the original request found in wctx.
         *  Redirect always gets redirected as GET. So, this is a limitation with this approach..
         *  Only GET requests work when redirected to ACS..
         */
        response.sendRedirect(wctx);
    }


	private void redirectToACS() throws IOException	{
		Utils.logDebug("Redirecting to ACS...", LOG);

		// Using wctx parameter..
		StringBuilder redirectURL = new StringBuilder(config.passiveRequestorEndPoint);
		redirectURL.append("?wa=wsignin1.0&wtrealm=");
		redirectURL.append(config.relyingPartyRealm);
		redirectURL.append("&wctx=");
		redirectURL.append(getCompleteRequestURL());

		Utils.logDebug("Redirecting to " + redirectURL.toString(), LOG);
		response.sendRedirect(redirectURL.toString());
	}




    String getCompleteRequestURL() {
        StringBuffer completeRequestURL = request.getRequestURL();
        String queryString = request.getQueryString();
        if (queryString != null && !queryString.isEmpty()) {
            completeRequestURL.append('?').append(queryString);
        }
        return completeRequestURL.toString();
    }

    SAMLAssertion getSAMLAssertionFromACSResponse() throws LogonFailureException {
        String securityTokenResponse = request.getParameter("wresult");
        Utils.logDebug("wsresult in the response from ACS is " + securityTokenResponse, LOG);

        if (securityTokenResponse == null) {
            return null;
        }

        // None of Java XML objects are thread-safe. Better to create instance on demand rather than caching.
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setNamespaceAware(true); // very important, must
        DocumentBuilder docBuilder;
        SAMLAssertion assertion = null;

        try {
            docBuilder = docBuilderFactory.newDocumentBuilder();
            Document respDoc = docBuilder.parse(new ByteArrayInputStream(Utils.getUTF8Bytes(securityTokenResponse)));
            // Find the response token
            Element responseToken = (Element) respDoc.getDocumentElement().getElementsByTagNameNS("http://schemas.xmlsoap.org/ws/2005/02/trust", "RequestedSecurityToken").item(0);
            assertion = SAMLAssertion.getAssertionFromSecurityToken(responseToken);
        } catch (Exception e) {
            Utils.logError("Exception while parsing the security token response from ACS.", e, LOG);
        }

        if (assertion == null) {
            throw new LogonFailureException("SAML Assertion not found in the response from ACS.");
        }

        logAssertionAttributes(assertion);
        return assertion;
    }


    void invokeChainWithRemoteUser(SAMLAssertion assertion) throws IOException, ServletException	{
        try {
            // set assertion as an attribute in the request
            request.setAttribute(ACS_SAML, Utils.getXMLStringFromNode(assertion.getAssertionXMLElement()));
        } catch(Exception e) {
            Utils.logError("Invalid Saml Content.", e, LOG);
            throw new ServletException("Invalid SAML Content");
        }

        final String remoteUser = AssertionUtil.getUserFromAssertion(assertion);
        Utils.logDebug("Invoking the request with remote user : " + remoteUser, LOG);
        HttpServletRequest httpRequestWithRemoteUser = new HttpServletRequestWrapper(request){
            public String getRemoteUser() {
                return remoteUser;
            }
        };

        final String subdomain = AssertionUtil.getSubdomainFromAssertion(assertion);
        request.setAttribute(ACS_SUBDOMAIN, subdomain);

        chain.doFilter(httpRequestWithRemoteUser, response);
    }
}