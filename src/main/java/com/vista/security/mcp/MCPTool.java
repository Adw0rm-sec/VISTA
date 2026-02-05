package com.vista.security.mcp;

import java.util.Map;

/**
 * Represents an MCP tool definition.
 */
public class MCPTool {
    private String name;
    private String description;
    private Map<String, Object> inputSchema;

    public MCPTool() {
    }

    public MCPTool(String name, String description, Map<String, Object> inputSchema) {
        this.name = name;
        this.description = description;
        this.inputSchema = inputSchema;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Map<String, Object> getInputSchema() {
        return inputSchema;
    }

    public void setInputSchema(Map<String, Object> inputSchema) {
        this.inputSchema = inputSchema;
    }

    @Override
    public String toString() {
        return "MCPTool{name='" + name + "', description='" + description + "'}";
    }
}
