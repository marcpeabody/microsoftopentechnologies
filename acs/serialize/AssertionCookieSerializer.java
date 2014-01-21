package com.microsoftopentechnologies.acs.serialize;

import com.microsoftopentechnologies.acs.federation.AssertionCompressor;
import com.microsoftopentechnologies.acs.saml.SAMLAssertion;
import com.microsoftopentechnologies.acs.util.Utils;
import com.microsoftopentechnologies.acs.xmldsig.TrustParameters;
import edu.emory.mathcs.backport.java.util.Collections;

import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AssertionCookieSerializer extends AssertionSerializer {
    private static final Logger LOG = Logger.getLogger(AssertionCookieSerializer.class.getName());
    /*
	 * Cookie size limit is in bytes. But the value we put in the cookie is Base64 encoded string, in which
	 * each character maps to a byte. So, we can treat the same limit for number of character as well.
	 * 4096 bytes is the standard size limit of cookie. This limit is including the name, value and other
	 * attributes of a cookie. So limiting the size of the value to 4000 bytes.
	 */
    private static final int MAX_COOKIE_SIZE = 4000;

    // Cookie names should be unique, should not clash with other cookie names
    public static final String COOKIE_PREFIX = "ACSFedAuth";

    private TrustParameters trustParams;
    private String domainForCookies;

    private Method setHttpOnlyMethod;

    public AssertionCookieSerializer(TrustParameters trustParams, String domainForCookies) {
        this.trustParams = trustParams;
        this.domainForCookies = domainForCookies;

        try {
            Method method = Cookie.class.getMethod("setHttpOnly", boolean.class);
            if("setHttpOnly".equalsIgnoreCase(method.getName()))
                setHttpOnlyMethod = method;
        }catch(NoSuchMethodException nsme) {
            Utils.logDebug("Got NoSuchMethodException, hence not setting httponly attribute on cookie", LOG);
        }catch(SecurityException se) {
            Utils.logDebug("Got SecurityException, hence not setting httponly attribute", LOG);
        }
    }

    public SAMLAssertion getAssertion(HttpServletRequest request) throws Exception {
        List<Cookie> assertionCookies = getAssertionCookies(request);
        SAMLAssertion assertion = null;

        try {
            // Sort these assertion cookies in the right order and extract content from all of them
            String deflatedAssertionContent = extractAssertionContentFromCookies(assertionCookies);
            assertion = AssertionCompressor.getAssertionFromDeflatedContent(deflatedAssertionContent, trustParams.getSecretKey());
        } catch (Exception e) {
            Utils.logError("Exception occured while building SAML Assertion from the cookie content", e, LOG);
            String cause = "Cookie content is not a valid SAML Assertion. " + e.getMessage();
            throw new Exception(cause);
        }

        logAssertion(assertion);

        return assertion;
    }


    public void saveAssertion(SAMLAssertion assertion, HttpServletRequest request, HttpServletResponse response, SecretKey secretKey) throws Exception {
        Utils.logDebug("Putting SAML Assertion in the cookie(s)", LOG);

        String deflatedAssertionContent = AssertionCompressor.deflateAssertionContent(assertion, secretKey);

        // Split it into blocks of size limit
        String[] splitPartsOfAssertion = Utils.splitText(deflatedAssertionContent, MAX_COOKIE_SIZE);
        Utils.logDebug(String.format("Assertion is split into %s cookies.", splitPartsOfAssertion.length), LOG);

        for (int i = 0; i < splitPartsOfAssertion.length; i++) {
            // Create one cookie for each part
            String cookieName = COOKIE_PREFIX + i;
            String cookieValue = splitPartsOfAssertion[i];
            makeCookie(response, cookieName, cookieValue);
        }

        //set no. of cookies that are set, can use this as additional check during verification
        int cookiesCount = splitPartsOfAssertion.length;
        makeCookie(response, COOKIE_PREFIX+cookiesCount, (cookiesCount+1)+"");
        Utils.logDebug("SAML Assertion put in the cookie(s)", LOG);
    }

    private void makeCookie(HttpServletResponse response, String key, String value) {
        Cookie cookie = new Cookie(key, value);
        if (domainForCookies != null) {
            cookie.setDomain(domainForCookies);
        }

        if (setHttpOnlyMethod != null) {
            try {
                setHttpOnlyMethod.invoke(cookie, true);
            } catch (Exception e) {
                Utils.logDebug("Attempt to call setHttpOnly method on Cookie failed.", LOG);
            }
        }
        response.addCookie(cookie);
    }


    private List<Cookie> getAssertionCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        ArrayList<Cookie> assertionCookies = null;
        if (cookies != null && cookies.length > 0) {
            assertionCookies = new ArrayList<Cookie>();
            for (Cookie cookie : cookies) {
                if (cookie.getName().startsWith(COOKIE_PREFIX)) {
                    assertionCookies.add(cookie);
                }
            }
        }
        if (assertionCookies != null && !assertionCookies.isEmpty()) {
            Utils.logDebug(String.format("Assertion present in cookies. Number of assertion cookies is %s. Building assertion from cookie content...", assertionCookies.size()), LOG);
            return assertionCookies;
        } else {
            return null;
        }
    }

	private String extractAssertionContentFromCookies(List<Cookie> assertionCookies) throws Exception	{
		// Sort all the cookies in the right order
		CookieComparator comparator = new CookieComparator();
		Collections.sort(assertionCookies, comparator);

		//Check if all the cookies that are set are retrieved
		if(!assertionCookies.isEmpty()) {
			Cookie cookieCount = assertionCookies.get(assertionCookies.size()-1);
			String expectedCookiesCount = cookieCount.getValue();
			if(Integer.parseInt(expectedCookiesCount) == assertionCookies.size()) {
				// All the cookies that are set are retrieved , removing content of last cookie
				// 1. check cookie names
				for(int i = 0 ; i < assertionCookies.size();i++) {
					Cookie cookie = assertionCookies.get(i);
					if(!cookie.getName().equalsIgnoreCase(COOKIE_PREFIX+i)) {
						throw new Exception("Cookie content is either not valid or malformed");
					}
				}
				assertionCookies.remove(assertionCookies.size()-1);
			}else{
				throw new Exception("Cookie content is not valid");
			}
		}

		// Append all cookie values in the sorted order
		StringBuffer contentBuffer = new StringBuffer();
		for (Cookie cookie: assertionCookies) {
			contentBuffer.append(cookie.getValue());
		}
		return contentBuffer.toString();
	}

    /**
     * To sort cookies.. Compares by comparing cookie values based on the number appended to the prefix.
     * Cookies with smaller numbers come first in the ordering.
     */
    private static class CookieComparator implements Comparator<Cookie> {
        private static final Logger LOG = Logger.getLogger(CookieComparator.class.getName());

        @Override
        public int compare(Cookie cookie1, Cookie cookie2) {
            int firstCookieNumber = getNumberAfterPrefix(cookie1.getName());
            int secondCookieNumber = getNumberAfterPrefix(cookie2.getName());
            return (firstCookieNumber - secondCookieNumber);
        }
        private int getNumberAfterPrefix(String cookieName) {
            String appendedValue = cookieName.substring(COOKIE_PREFIX.length());
            try {
                return Integer.parseInt(appendedValue);
            } catch (NumberFormatException nfe) {
				/*
				 *  Return 0 for such cookies. One such cookie is allowed. If more than one is present, only the last one
				 *  is considered. Others are ignored.
				 */
                Utils.logWarn("An assertion cookie has no number..", nfe, LOG);
                return 0;
            }
        }
    }


}