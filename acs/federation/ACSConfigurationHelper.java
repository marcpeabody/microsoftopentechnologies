package com.microsoftopentechnologies.acs.federation;

import com.microsoftopentechnologies.acs.serialize.AssertionCookieSerializer;
import com.microsoftopentechnologies.acs.serialize.AssertionSerializer;
import com.microsoftopentechnologies.acs.serialize.AssertionSessionSerializer;
import com.microsoftopentechnologies.acs.util.Utils;
import com.microsoftopentechnologies.acs.xmldsig.TrustParameters;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ACSConfigurationHelper {
    private static final Logger LOG = Logger.getLogger(ACSConfigurationHelper.class.getName());

    public static final String EMBEDDED_CERT_LOC = "WEB-INF/cert/_acs_signing.cer";

    private static final String PASSIVE_REQUESTOR_ENDPOINT = "PassiveRequestorEndpoint";
    // RELYING_PART_REALM is for backwards compatibility for typo of old code
    private static final String RELYING_PART_REALM = "RelyingPartRealm";
    private static final String RELYING_PARTY_REALM = "RelyingPartyRealm";
    private static final String CERTIFICATE_PATH = "CertificatePath";
    private static final String SECRET_KEY = "SecretKey";
    private static final String ALLOW_HTTP = "AllowHTTP";
    private static final String ASSERTION_SERIALIZATION_TYPE = "AssertionSerializationType"; // session (default) or cookie

    protected String passiveRequestorEndPoint;
    protected String relyingPartyRealm;
    protected String certificatePath;
    protected String secretKey;
    protected TrustParameters trustParams;
    protected String domainForCookies;
    protected boolean allowHttp = false;
    private boolean isAssertionSerializationCookieBased = true;

    public ACSConfigurationHelper(FilterConfig filterConfig) throws ServletException {

        passiveRequestorEndPoint = filterConfig.getInitParameter(PASSIVE_REQUESTOR_ENDPOINT);
        Utils.logInfo("Passive Requestor Endpoint is:" + passiveRequestorEndPoint, LOG);
        if (passiveRequestorEndPoint == null) {
            throw new ServletException(PASSIVE_REQUESTOR_ENDPOINT + " init parameter not provided in the filter configuration.");
        }
        // Remove query parameters if any
        passiveRequestorEndPoint = (passiveRequestorEndPoint != null && passiveRequestorEndPoint.indexOf('?') > 0 ) ?
                passiveRequestorEndPoint.substring(0, passiveRequestorEndPoint.indexOf('?')):
                passiveRequestorEndPoint;

        relyingPartyRealm = filterConfig.getInitParameter(RELYING_PART_REALM);
        if (relyingPartyRealm == null) {
            relyingPartyRealm = filterConfig.getInitParameter(RELYING_PARTY_REALM);
        }
        Utils.logInfo("Relying Party Realm is:" + relyingPartyRealm, LOG);
        if (relyingPartyRealm == null) {
            throw new ServletException(RELYING_PARTY_REALM + " init parameter not provided in the filter configuration.");
        } else {
            Pattern pattern = Pattern.compile("https?://([\\-a-z0-9\\.]*)");
            Matcher matcher = pattern.matcher(relyingPartyRealm);
            if (matcher.find() && matcher.groupCount() == 1) {
                domainForCookies = "." + matcher.group(1);
            }
        }

        certificatePath = filterConfig.getInitParameter(CERTIFICATE_PATH);
        Utils.logInfo("Certificate path:" + certificatePath, LOG);
        if (certificatePath == null) {
            //1. check for embedded cert and if exists set certPath to cert/acs_signing.cer
            if(filterConfig.getServletContext().getResourceAsStream(EMBEDDED_CERT_LOC) != null )
                certificatePath = EMBEDDED_CERT_LOC;
            else
                throw new ServletException(CERTIFICATE_PATH + " init parameter not proivded in the filter configuration" +
                        " or Embedded Cert is not found at /WEB-INF/cert/_acs_signing.cer");
        }

        secretKey = filterConfig.getInitParameter(SECRET_KEY);
        if (secretKey == null) {
            throw new ServletException(SECRET_KEY + " init parameter not provided in the filter configuration.");
        }

        allowHttp = Boolean.parseBoolean(filterConfig.getInitParameter(ALLOW_HTTP));

        //create keystore
        Key publicKey = getPublicKey(certificatePath,filterConfig);
        trustParams = new TrustParameters(publicKey,Utils.getSecretKey(secretKey),allowHttp,relyingPartyRealm);

        String assertionSerializationType = filterConfig.getInitParameter(ASSERTION_SERIALIZATION_TYPE);
        if (assertionSerializationType != null && assertionSerializationType.trim().toLowerCase().startsWith("session")) {
            isAssertionSerializationCookieBased = false;
        }
    }

    public AssertionSerializer getAssertionSerializer() {
        if (isAssertionSerializationCookieBased) {
            return new AssertionCookieSerializer(trustParams, domainForCookies);
        } else {
            return new AssertionSessionSerializer(trustParams);
        }
    }

    public static Key getPublicKey(String certificatePath, FilterConfig filterConfig) throws ServletException {
        Certificate certificate = null;
        InputStream is  = null;
        try	{
            if(certificatePath != null)
                certificatePath = certificatePath.replace('\\', '/');
            certificatePath = getCertificatePath(certificatePath);
            File certFile   = new File(certificatePath);
            if(certFile.isAbsolute())
                is = new FileInputStream(certificatePath);
            else
                is = filterConfig.getServletContext().getResourceAsStream(EMBEDDED_CERT_LOC);
            BufferedInputStream bufferedInputStream = new BufferedInputStream(is);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            while (bufferedInputStream.available() > 0) {
                certificate = certificateFactory.generateCertificate(bufferedInputStream);
            }
        } catch (FileNotFoundException fnfe)	{
            throw new ServletException("File not found "+certificatePath);
        } catch (Throwable t)	{
            throw new ServletException("Error while retrieving public key from certificate");
        }
        return certificate.getPublicKey();
    }


    public static String getCertificatePath(String rawPath) {
        String certPath = null;
        if (rawPath != null && rawPath.length() > 0) {
            String[] result = rawPath.split("/");
            StringBuilder  path = new StringBuilder();

            for (int x = 0; x < result.length; x++) {
                if (result[x].startsWith("${env")) {
                    String envValue = System.getenv(result[x].substring("${env.".length(), (result[x].length() - 1)));
                    path.append(envValue).append(File.separator);
                } else {
                    path.append(result[x]).append(File.separator);
                }
            }

            //Delete last trailing slash
            path = path.deleteCharAt(path.length() - 1);
            certPath = path.toString();
        }
        return certPath;
    }
}
