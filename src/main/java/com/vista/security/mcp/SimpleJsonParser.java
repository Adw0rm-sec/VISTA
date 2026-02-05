package com.vista.security.mcp;

import java.util.*;

/**
 * Simple JSON parser without external dependencies.
 * Handles basic JSON parsing for MCP protocol.
 */
public class SimpleJsonParser {

    public static Map<String, Object> parseObject(String json) {
        if (json == null || json.trim().isEmpty()) {
            return new HashMap<>();
        }
        
        json = json.trim();
        if (!json.startsWith("{") || !json.endsWith("}")) {
            throw new IllegalArgumentException("Invalid JSON object");
        }
        
        return parseObjectInternal(json, 1, json.length() - 1);
    }

    private static Map<String, Object> parseObjectInternal(String json, int start, int end) {
        Map<String, Object> result = new HashMap<>();
        int i = start;
        
        while (i < end) {
            // Skip whitespace
            while (i < end && Character.isWhitespace(json.charAt(i))) {
                i++;
            }
            
            if (i >= end || json.charAt(i) == '}') {
                break;
            }
            
            // Parse key
            if (json.charAt(i) != '"') {
                throw new IllegalArgumentException("Expected key at position " + i);
            }
            
            int keyStart = i + 1;
            int keyEnd = findStringEnd(json, keyStart);
            String key = json.substring(keyStart, keyEnd);
            i = keyEnd + 1;
            
            // Skip whitespace and colon
            while (i < end && (Character.isWhitespace(json.charAt(i)) || json.charAt(i) == ':')) {
                i++;
            }
            
            // Parse value
            ParseResult valueResult = parseValue(json, i, end);
            result.put(key, valueResult.value);
            i = valueResult.endIndex;
            
            // Skip whitespace and comma
            while (i < end && (Character.isWhitespace(json.charAt(i)) || json.charAt(i) == ',')) {
                i++;
            }
        }
        
        return result;
    }

    private static ParseResult parseValue(String json, int start, int end) {
        int i = start;
        
        // Skip whitespace
        while (i < end && Character.isWhitespace(json.charAt(i))) {
            i++;
        }
        
        if (i >= end) {
            return new ParseResult(null, i);
        }
        
        char c = json.charAt(i);
        
        // String
        if (c == '"') {
            int strStart = i + 1;
            int strEnd = findStringEnd(json, strStart);
            String value = json.substring(strStart, strEnd);
            return new ParseResult(unescapeJson(value), strEnd + 1);
        }
        
        // Object
        if (c == '{') {
            int objEnd = findMatchingBrace(json, i, end);
            Map<String, Object> obj = parseObjectInternal(json, i + 1, objEnd);
            return new ParseResult(obj, objEnd + 1);
        }
        
        // Array
        if (c == '[') {
            int arrEnd = findMatchingBracket(json, i, end);
            List<Object> arr = parseArray(json, i + 1, arrEnd);
            return new ParseResult(arr, arrEnd + 1);
        }
        
        // null
        if (json.startsWith("null", i)) {
            return new ParseResult(null, i + 4);
        }
        
        // true
        if (json.startsWith("true", i)) {
            return new ParseResult(true, i + 4);
        }
        
        // false
        if (json.startsWith("false", i)) {
            return new ParseResult(false, i + 5);
        }
        
        // Number
        int numEnd = i;
        while (numEnd < end && (Character.isDigit(json.charAt(numEnd)) || 
               json.charAt(numEnd) == '-' || json.charAt(numEnd) == '.' || 
               json.charAt(numEnd) == 'e' || json.charAt(numEnd) == 'E' ||
               json.charAt(numEnd) == '+')) {
            numEnd++;
        }
        
        if (numEnd > i) {
            String numStr = json.substring(i, numEnd);
            try {
                if (numStr.contains(".") || numStr.contains("e") || numStr.contains("E")) {
                    return new ParseResult(Double.parseDouble(numStr), numEnd);
                } else {
                    return new ParseResult(Long.parseLong(numStr), numEnd);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid number: " + numStr);
            }
        }
        
        throw new IllegalArgumentException("Unexpected character at position " + i + ": " + c);
    }

    private static List<Object> parseArray(String json, int start, int end) {
        List<Object> result = new ArrayList<>();
        int i = start;
        
        while (i < end) {
            // Skip whitespace
            while (i < end && Character.isWhitespace(json.charAt(i))) {
                i++;
            }
            
            if (i >= end || json.charAt(i) == ']') {
                break;
            }
            
            ParseResult valueResult = parseValue(json, i, end);
            result.add(valueResult.value);
            i = valueResult.endIndex;
            
            // Skip whitespace and comma
            while (i < end && (Character.isWhitespace(json.charAt(i)) || json.charAt(i) == ',')) {
                i++;
            }
        }
        
        return result;
    }

    private static int findStringEnd(String json, int start) {
        int i = start;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '"' && (i == start || json.charAt(i - 1) != '\\')) {
                return i;
            }
            i++;
        }
        throw new IllegalArgumentException("Unterminated string starting at " + start);
    }

    private static int findMatchingBrace(String json, int start, int end) {
        int depth = 1;
        int i = start + 1;
        boolean inString = false;
        
        while (i < end && depth > 0) {
            char c = json.charAt(i);
            
            if (c == '"' && (i == 0 || json.charAt(i - 1) != '\\')) {
                inString = !inString;
            } else if (!inString) {
                if (c == '{') {
                    depth++;
                } else if (c == '}') {
                    depth--;
                }
            }
            
            i++;
        }
        
        if (depth != 0) {
            throw new IllegalArgumentException("Unmatched braces");
        }
        
        return i - 1;
    }

    private static int findMatchingBracket(String json, int start, int end) {
        int depth = 1;
        int i = start + 1;
        boolean inString = false;
        
        while (i < end && depth > 0) {
            char c = json.charAt(i);
            
            if (c == '"' && (i == 0 || json.charAt(i - 1) != '\\')) {
                inString = !inString;
            } else if (!inString) {
                if (c == '[') {
                    depth++;
                } else if (c == ']') {
                    depth--;
                }
            }
            
            i++;
        }
        
        if (depth != 0) {
            throw new IllegalArgumentException("Unmatched brackets");
        }
        
        return i - 1;
    }

    private static String unescapeJson(String str) {
        return str.replace("\\\"", "\"")
                  .replace("\\\\", "\\")
                  .replace("\\n", "\n")
                  .replace("\\r", "\r")
                  .replace("\\t", "\t");
    }

    private static class ParseResult {
        Object value;
        int endIndex;
        
        ParseResult(Object value, int endIndex) {
            this.value = value;
            this.endIndex = endIndex;
        }
    }
}
