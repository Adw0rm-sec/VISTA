package com.burpraj.util;

import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.nio.charset.StandardCharsets;

public class HttpFormat {
    public static String requestToText(IExtensionHelpers helpers, byte[] request) {
        if (request == null) return "(no request)";
        IRequestInfo reqInfo = helpers.analyzeRequest(request);
        int bodyOffset = reqInfo.getBodyOffset();
        
        String headers = String.join("\r\n", reqInfo.getHeaders());
        String body = new String(request, bodyOffset, request.length - bodyOffset, StandardCharsets.ISO_8859_1);
        return headers + "\r\n\r\n" + body;
    }

    public static String responseToText(IExtensionHelpers helpers, byte[] response) {
        if (response == null) return "(no response)";
        IResponseInfo respInfo = helpers.analyzeResponse(response);
        int bodyOffset = respInfo.getBodyOffset();
        
        String headers = String.join("\r\n", respInfo.getHeaders());
        String body = new String(response, bodyOffset, response.length - bodyOffset, StandardCharsets.ISO_8859_1);
        return headers + "\r\n\r\n" + body;
    }

    public static String prepareForAi(String raw, boolean stripSensitive, int maxChars) {
        if (raw == null) return "";
        String[] parts = raw.split("\r?\n\r?\n", 2);
        String headers = parts.length > 0 ? parts[0] : "";
        String body = parts.length > 1 ? parts[1] : "";
        if (stripSensitive) {
            headers = stripHeaders(headers, new String[]{"authorization", "cookie", "set-cookie"});
        }
        String combined = headers + "\n\n" + body;
        if (combined.length() > maxChars) {
            combined = combined.substring(0, maxChars) + "\n...[truncated]...";
        }
        return combined;
    }

    private static String stripHeaders(String headers, String[] names) {
        String[] lines = headers.split("\r?\n");
        StringBuilder out = new StringBuilder();
        for (String line : lines) {
            String lc = line.toLowerCase();
            boolean skip = false;
            for (String n : names) {
                if (lc.startsWith(n + ":")) { skip = true; break; }
            }
            if (!skip) {
                out.append(line).append("\n");
            }
        }
        return out.toString().trim();
    }
}
