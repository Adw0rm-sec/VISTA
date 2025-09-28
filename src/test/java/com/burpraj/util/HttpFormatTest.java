package com.burpraj.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HttpFormatTest {
    static class HelpersMock implements burp.IExtensionHelpers {
        public burp.IRequestInfo analyzeRequest(byte[] request) { return new Req(request); }
        public burp.IRequestInfo analyzeRequest(burp.IHttpRequestResponse r) { return null; }
        public burp.IResponseInfo analyzeResponse(byte[] response) { return new Resp(response); }
        // Unused methods stubbed as no-op
    }
    static class Req implements burp.IRequestInfo {
        private final byte[] raw; Req(byte[] r){this.raw=r;} public java.util.List<String> getHeaders(){return java.util.List.of("GET /test HTTP/1.1","Host: example.com","Cookie: secret=1","Authorization: Bearer abc");} public int getBodyOffset(){return String.join("\r\n",getHeaders()).getBytes().length+4;} public java.util.List<String> getParameters(){return java.util.List.of();}
    }
    static class Resp implements burp.IResponseInfo {
        private final byte[] raw; Resp(byte[] r){this.raw=r;} public java.util.List<String> getHeaders(){return java.util.List.of("HTTP/1.1 200 OK","Set-Cookie: s=1");} public int getBodyOffset(){return String.join("\r\n",getHeaders()).getBytes().length+4;} public short getStatusCode(){return 200;} public String getStatedMimeType(){return "text";} public String getInferredMimeType(){return "text";}
    }

    @Test void stripAndTruncate() {
        HelpersMock h = new HelpersMock();
        // Build raw request consistent with mocked headers
        String headers = String.join("\r\n", new Req(new byte[0]).getHeaders());
        String raw = headers + "\r\n\r\nBODYDATA";
        String req = HttpFormat.requestToText(h, raw.getBytes());
        String prepared = HttpFormat.prepareForAi(req, true, 60);
        String lower = prepared.toLowerCase();
        assertFalse(lower.contains("authorization:"));
        assertFalse(lower.contains("cookie:"));
        assertTrue(prepared.contains("BODYDATA") || prepared.contains("...[truncated]..."));
    }
}
