package com.microsoftopentechnologies.acs.federation;

import com.microsoftopentechnologies.acs.saml.SAMLAssertion;
import com.microsoftopentechnologies.acs.util.Base64;
import com.microsoftopentechnologies.acs.util.DeflaterUtils;
import com.microsoftopentechnologies.acs.util.Utils;
import org.w3c.dom.Document;

import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;

/**
 * Created with IntelliJ IDEA.
 * User: mpeabody
 * Date: 1/20/14
 * Time: 11:31 AM
 * To change this template use File | Settings | File Templates.
 */
public class AssertionCompressor {

    public static SAMLAssertion getAssertionFromDeflatedContent(String deflatedAssertionXML, SecretKey secretKey)
            throws Exception {
        byte[] assertionXML = inflateAssertionXML(deflatedAssertionXML);
        assertionXML        = Utils.decrypt(secretKey, assertionXML);
//        Utils.logDebug("Assertion received in the cookie is :" + Utils.getStringFromUTF8Bytes(assertionXML), LOG);

        // load into xml
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setNamespaceAware(true); // very important
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        Document doc = docBuilder.parse(new ByteArrayInputStream(assertionXML));
        return SAMLAssertion.getAssertionFromAssertionDocument(doc);
    }

    public static String deflateAssertionContent(SAMLAssertion assertion, SecretKey secretKey) throws Exception {
        byte[] serializedAssertionContent = assertion.getSerializedContent();
        serializedAssertionContent        = Utils.encrypt(secretKey, serializedAssertionContent);
        String deflatedAssertionContent   = deflateAssertionXML(serializedAssertionContent);
        return deflatedAssertionContent;
    }


    private static String deflateAssertionXML(byte[] assertionXMLContent)	{
        byte[] deflatedBytes = DeflaterUtils.deflate(assertionXMLContent);

        String base64EncodedDeflated = Base64.encode(deflatedBytes);
//		Remove all \r\n characters.. they are illegal in cookie values
        base64EncodedDeflated = Utils.removeCRLFsInBase64EncodedText(base64EncodedDeflated);
        return base64EncodedDeflated;
    }

    private static byte[] inflateAssertionXML(String deflatedAssertionXML) throws IOException, DataFormatException {
        byte[] deflatedBytes = Base64.decode(deflatedAssertionXML);
        return DeflaterUtils.inflate(deflatedBytes);
    }

}
