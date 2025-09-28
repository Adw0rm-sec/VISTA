package com.burpraj.util;

public class VulnTemplates {
    // Condensed/curated snippets from provided .jinja guides to enrich prompts.
    public static final String CSRF = String.join("\n",
            "CSRF - exploitation notes:",
            "- Check token presence/validation, SameSite, Origin/Referer checks",
            "- JSON/multipart CSRF tricks; method overrides; text/plain",
            "Validation: working PoC form/request that performs sensitive action.");

    public static final String IDOR = String.join("\n",
            "IDOR - enumeration and access checks:",
            "- Numeric/UUID/encoded IDs in URL, body, headers, cookies, JWT",
            "- Boundary values, array/object forms, format switching",
            "Validation: access other users' data/functionality consistently.");

    public static final String SQLI = String.join("\n",
            "SQL Injection - techniques:",
            "- Boolean/time/error-based, UNION enumeration",
            "- DB-specific tricks (MySQL, MSSQL, PostgreSQL, Oracle)",
            "Validation: extract version/data or demonstrate query manipulation.");

    public static final String SSRF = String.join("\n",
            "SSRF - internal access and metadata:",
            "- Parameters like url/link/path; file import/export, webhooks",
            "- Cloud metadata AWS/GCP/Azure headers; protocols gopher/file/dict",
            "Validation: internal resource access or OOB callbacks.");

    public static final String XSS = String.join("\n",
            "XSS - modern exploitation cues:",
            "- Contexts: HTML/attr/JS/URL/CSS; DOM sinks innerHTML/document.write",
            "- Bypasses: tag/event variants, string/keyword/paren tricks, CSP gadgets",
            "Validation: working payload with verification and safer variants.");

    public static String composeCheatsheet() {
        return String.join("\n\n",
                CSRF, IDOR, SQLI, SSRF, XSS);
    }
}
