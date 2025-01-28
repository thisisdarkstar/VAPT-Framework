export const vulns = [
    {
        "id": "ALNI:A7:2021",
        "title": "Account Lockout Not Implemented",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-123",
            "owasp_category": "A7 - Insufficient Authentication and Session Management"
        },
        "details": {
            "description": "Account lockout mechanisms are not implemented, allowing attackers to perform brute force attacks without limitation.",
            "impact": "Without an account lockout, attackers can continuously guess passwords and gain unauthorized access to user accounts.",
            "recommendations": "Implement account lockout after a predefined number of failed login attempts. Refer to guidelines from OWASP: https://owasp.org/www-project-top-ten/",
            "reference": "https://owasp.org/www-community/vulnerabilities/Account_Lockout_Not_Implemented"
        },
        "tool": "Hydra"
    },
    {
        "id": "APAA:A10:2021",
        "title": "Admin Panel Accessible",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-284",
            "owasp_category": "A10 - Insufficient Security Configuration"
        },
        "details": {
            "description": "The admin panel is accessible without proper authentication, exposing sensitive functionality to unauthorized users.",
            "impact": "Unauthorized access to the admin panel can lead to data breaches, unauthorized changes, and system compromise.",
            "recommendations": "Secure the admin panel by enforcing strong authentication mechanisms (e.g., two-factor authentication) and limit access using IP whitelisting. Additional resources: https://owasp.org/www-project-top-ten/",
            "reference": "https://owasp.org/www-community/vulnerabilities/Insufficient_Security_Configuration"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "ACLI:ACR:2021",
        "title": "Application Crashes on Large Inputs",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.0,
            "cwe_id": "CWE-400",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "The application crashes when provided with large inputs, possibly indicating a lack of proper input validation or handling.",
            "impact": "If not properly managed, this can lead to Denial of Service (DoS) conditions, where legitimate users cannot access the application.",
            "recommendations": "Validate and sanitize all user inputs, especially size limits, and implement appropriate error handling for abnormal input sizes. Check OWASP's guidelines on DoS prevention: https://owasp.org/www-project-top-ten/",
            "reference": "https://owasp.org/www-community/vulnerabilities/Denial_of_Service"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "ALDO:ADoS:2021",
        "title": "Application-Level Denial of Service (DoS)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.5,
            "cwe_id": "CWE-400",
            "owasp_category": "A6 - Vulnerable Components"
        },
        "details": {
            "description": "The application is vulnerable to application-level Denial of Service (DoS) attacks due to inadequate resource limits or input validation.",
            "impact": "An attacker can trigger excessive resource consumption, causing the application to become unresponsive and unavailable to legitimate users.",
            "recommendations": "Implement rate-limiting mechanisms, input size validation, and stress testing to avoid DoS vulnerabilities. Resources: https://owasp.org/www-project-top-ten/",
            "reference": "https://owasp.org/www-community/vulnerabilities/Denial_of_Service"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "BFF:BRF:2021",
        "title": "Backup File Found",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-22",
            "owasp_category": "A9 - Using Components with Known Vulnerabilities"
        },
        "details": {
            "description": "Backup files containing sensitive data or system configurations are found within the application, potentially allowing attackers to access sensitive information.",
            "impact": "Backup files may contain sensitive data that can be exploited by an attacker to gain unauthorized access or compromise the system.",
            "recommendations": "Ensure that backup files are stored securely or deleted after use. Sensitive files should not be included in web directories. More info: https://owasp.org/www-project-top-ten/",
            "reference": "https://owasp.org/www-community/vulnerabilities/Backup_File_Found"
        },
        "tool": "Nikto"
    },
    {
        "id": "BFA:BRF:2021",
        "title": "Brute Force Attack Possible",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-307",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "The application allows brute force attempts without implementing rate limiting or account lockout mechanisms.",
            "impact": "Attackers can attempt numerous login credentials, potentially gaining unauthorized access to user accounts or administrative functions.",
            "recommendations": "Implement account lockout and rate limiting for failed login attempts to mitigate brute force attacks. See OWASP guidelines for authentication security: https://owasp.org/www-project-top-ten/",
            "reference": "https://owasp.org/www-community/vulnerabilities/Brute_Force_Attack_Possible"
        },
        "tool": "Hydra"
    },
    {
        "id": "BOF:BUF:2021",
        "title": "Buffer Overflow",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-120",
            "owasp_category": "A4 - Insecure Direct Object Reference"
        },
        "details": {
            "description": "The application is vulnerable to buffer overflow attacks, where an attacker can overwrite memory and execute arbitrary code.",
            "impact": "Buffer overflow attacks can lead to unauthorized execution of arbitrary code, system crashes, and privilege escalation.",
            "recommendations": "Ensure proper bounds checking on all user input to prevent buffer overflow vulnerabilities. Resources: https://owasp.org/www-project-top-ten/",
            "reference": "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow"
        },
        "tool": "GDB"
    },
    {
        "id": "CBP:CBY:2021",
        "title": "CAPTCHA Bypass",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-540",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "The CAPTCHA mechanism in place can be bypassed, allowing automated attacks such as brute force or credential stuffing.",
            "impact": "Bypassing CAPTCHA results in an attacker being able to perform automated login attempts without restriction.",
            "recommendations": "Ensure CAPTCHA mechanisms are properly configured, implement multi-factor authentication (MFA), and use advanced CAPTCHA technologies (e.g., reCAPTCHA).",
            "reference": "https://owasp.org/www-community/vulnerabilities/Captcha_Bypass"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "CJX:CJX:2021",
        "title": "Clickjacking",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.5,
            "cwe_id": "CWE-1021",
            "owasp_category": "A8 - Cross-Site Request Forgery (CSRF)"
        },
        "details": {
            "description": "The application is vulnerable to clickjacking, where an attacker can trick users into clicking on hidden or disguised UI elements.",
            "impact": "Clickjacking can lead to unintended user actions, such as changing settings or submitting sensitive information.",
            "recommendations": "Use the `X-Frame-Options` header to prevent the site from being embedded in iframes. Consider adding frame busting JavaScript.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Clickjacking"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "CIN:CIN:2021",
        "title": "Command Injection",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.5,
            "cwe_id": "CWE-78",
            "owasp_category": "A3 - Sensitive Data Exposure"
        },
        "details": {
            "description": "Command injection vulnerabilities allow attackers to execute arbitrary commands on the host operating system through user input.",
            "impact": "Command injection can lead to unauthorized system access, data loss, or remote code execution.",
            "recommendations": "Validate and sanitize all user inputs, particularly those used in system commands. Refer to OWASP for guidelines: https://owasp.org/www-project-top-ten/",
            "reference": "https://owasp.org/www-community/vulnerabilities/Command_Injection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "CSRF:CSF:2021",
        "title": "Cross-Site Request Forgery (CSRF)",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.5,
            "cwe_id": "CWE-352",
            "owasp_category": "A8 - Cross-Site Request Forgery (CSRF)"
        },
        "details": {
            "description": "CSRF attacks allow an attacker to trick a user into making unwanted requests on a website where they are authenticated, leading to unauthorized actions.",
            "impact": "CSRF can lead to unauthorized actions being performed on behalf of the user, such as changing account settings or making transactions.",
            "recommendations": "Use anti-CSRF tokens for state-changing requests and ensure all critical actions require explicit user interaction.",
            "reference": "https://owasp.org/www-community/attacks/csrf"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "XSR:XSR:2021",
        "title": "Cross-Site Scripting (XSS) - Reflected",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-79",
            "owasp_category": "A7 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "Reflected XSS allows attackers to inject malicious scripts into web pages that execute when a user visits a manipulated URL.",
            "impact": "An attacker can steal session tokens, perform phishing attacks, or perform any action as the victim user in the context of their browser.",
            "recommendations": "Sanitize and escape all user inputs, particularly those included in URLs, and implement Content Security Policy (CSP).",
            "reference": "https://owasp.org/www-community/attacks/xss"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "XSS:XSS:2021",
        "title": "Cross-Site Scripting (XSS) - Stored",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.5,
            "cwe_id": "CWE-79",
            "owasp_category": "A7 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "Stored XSS occurs when user-supplied data is stored by the application and then executed in another user's browser when they load the data.",
            "impact": "Stored XSS can lead to the execution of malicious scripts, potentially allowing attackers to hijack user sessions or inject malware.",
            "recommendations": "Always validate, sanitize, and escape user-generated content before storing it, and use HTTP-only, Secure, SameSite cookies for session management.",
            "reference": "https://owasp.org/www-community/attacks/xss"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "XSD:XSD:2021",
        "title": "Cross-Site Scripting (XSS) - DOM Based",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.2,
            "cwe_id": "CWE-79",
            "owasp_category": "A7 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "DOM-based XSS happens when data from the document object model (DOM) is manipulated in an unsafe way, leading to execution of malicious JavaScript.",
            "impact": "This type of XSS is executed client-side and can lead to session hijacking or data theft, similar to other types of XSS.",
            "recommendations": "Use secure coding practices, such as sanitizing user inputs and validating DOM manipulation actions to prevent XSS vulnerabilities.",
            "reference": "https://owasp.org/www-community/attacks/xss"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "CRD:CRD:2021",
        "title": "Credential Disclosure",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-522",
            "owasp_category": "A6 - Sensitive Data Exposure"
        },
        "details": {
            "description": "Sensitive credentials such as passwords or API keys are exposed through improper handling or storage.",
            "impact": "Credential disclosure can allow attackers to impersonate legitimate users, gain unauthorized access, and escalate privileges.",
            "recommendations": "Use proper encryption to store credentials and never expose them in code, URL parameters, or logs.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Exposure_of_Sensitive_Information"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "COH:COH:2021",
        "title": "Credentials Over HTTP",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.5,
            "cwe_id": "CWE-319",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Credentials, such as passwords, are transmitted over HTTP without encryption, allowing attackers to intercept them during transmission.",
            "impact": "Interception of credentials can lead to unauthorized access, data theft, and potential account takeover.",
            "recommendations": "Always use HTTPS to encrypt data transmission and prevent credential interception. Implement HTTP Strict Transport Security (HSTS).",
            "reference": "https://owasp.org/www-community/vulnerabilities/Insufficient_Transport_Layer_Protection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "CORS:CORS:2021",
        "title": "Cross-Origin Resource Sharing (CORS) Misconfiguration",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-345",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "A misconfiguration in Cross-Origin Resource Sharing (CORS) can allow unauthorized domains to access sensitive resources.",
            "impact": "An attacker can exploit CORS misconfiguration to access sensitive information or perform malicious actions on behalf of the user.",
            "recommendations": "Properly configure CORS headers to restrict access to trusted domains only. Be sure to validate and secure the access controls.",
            "reference": "https://owasp.org/www-community/attacks/csrf"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "DC:DC:2021",
        "title": "Default Credentials",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-255",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "The application or system is using default credentials that have not been changed, providing attackers with an easy access point.",
            "impact": "Default credentials can easily be exploited, leading to unauthorized access to sensitive systems and data.",
            "recommendations": "Change default credentials immediately after installation and implement secure password policies to ensure strong authentication.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Default_Credentials"
        },
        "tool": "Hydra"
    },
    {
        "id": "DL:DL:2021",
        "title": "Directory Listing",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.5,
            "cwe_id": "CWE-548",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "The application is improperly configured to allow directory listing, exposing files and directories that should not be publicly accessible.",
            "impact": "Sensitive information, configuration files, or source code may be exposed to unauthorized users.",
            "recommendations": "Disable directory listing on all servers and ensure proper file access controls are in place.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Directory_Listing"
        },
        "tool": "Nikto"
    },
    {
        "id": "ES:ES:2021",
        "title": "Email Spoofing",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.5,
            "cwe_id": "CWE-1183",
            "owasp_category": "A4 - Insecure Direct Object Reference"
        },
        "details": {
            "description": "Email spoofing allows attackers to forge the sender's address, making it appear as if the email is coming from a trusted source.",
            "impact": "Spoofed emails can be used to perform phishing attacks, deceive recipients, and gather sensitive information.",
            "recommendations": "Implement email authentication mechanisms like SPF, DKIM, and DMARC to prevent spoofing and ensure email authenticity.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Email_Spoofing"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "FDI:FDI:2021",
        "title": "File Download Injection",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-526",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "File Download Injection occurs when attackers manipulate file download mechanisms to serve malicious files or unauthorized content.",
            "impact": "Attackers can inject files to be downloaded by users, which could lead to data breaches, malware infections, or unauthorized access.",
            "recommendations": "Use proper validation to restrict file downloads to known safe locations, and ensure file types are checked before download.",
            "reference": "https://owasp.org/www-community/vulnerabilities/File_Download_Injection"
        },
        "tool": "Burp Suite"
    },

    {
        "id": "FIPT:FIPT:2021",
        "title": "File Inclusion - Path Traversal",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-22",
            "owasp_category": "A7 - Insufficient Logging & Monitoring"
        },
        "details": {
            "description": "Path Traversal vulnerabilities allow attackers to access arbitrary files on the server by manipulating file paths.",
            "impact": "Attackers can gain access to sensitive files, configuration files, and potentially execute arbitrary code on the server.",
            "recommendations": "Validate all file paths, avoid user input in file path parameters, and implement access control checks.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Path_Traversal"
        },
        "tool": "OWASP ZAP"
    },

    {
        "id": "FURB:FURB:2021",
        "title": "File Upload - Content-Type Restriction Bypass",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-444",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "This vulnerability allows attackers to upload malicious files by bypassing content-type restrictions.",
            "impact": "Malicious files can be uploaded and executed on the server, leading to a potential remote code execution or compromise.",
            "recommendations": "Validate file content type on both client and server sides, and ensure files are scanned for malware before being processed.",
            "reference": "https://owasp.org/www-community/vulnerabilities/File_Upload_Security_Best_Practices"
        },
        "tool": "Burp Suite"
    },

    {
        "id": "FUE:FUE:2021",
        "title": "File Upload - Double Extension",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-434",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Double extension vulnerabilities occur when a file is uploaded with a misleading extension, such as 'example.jpg.php'.",
            "impact": "Attackers can upload files that appear to be harmless images, but are actually executable PHP scripts that could lead to server compromise.",
            "recommendations": "Disallow file extensions that are not required for your application and restrict executable file uploads.",
            "reference": "https://owasp.org/www-community/vulnerabilities/File_Upload_Security_Best_Practices"
        },
        "tool": "OWASP ZAP"
    },

    {
        "id": "FUMN:FUMN:2021",
        "title": "File Upload - Magic Number",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.2,
            "cwe_id": "CWE-434",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Magic number vulnerabilities occur when a file's content type is identified based on its content rather than the file extension, which can be bypassed.",
            "impact": "An attacker can upload malicious files with disguised content types that can be executed on the server.",
            "recommendations": "Use file signature verification or magic number checks to validate the actual file content type before processing uploads.",
            "reference": "https://owasp.org/www-community/vulnerabilities/File_Upload_Security_Best_Practices"
        },
        "tool": "Burp Suite"
    },

    {
        "id": "FUM:FUM:2021",
        "title": "File Upload - Malware",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.5,
            "cwe_id": "CWE-434",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Malware can be uploaded through vulnerable file upload mechanisms if file validation and scanning are not properly implemented.",
            "impact": "Malicious files uploaded to the server could lead to malware infection, data theft, or remote code execution.",
            "recommendations": "Use strong anti-malware scanners, validate file types, and restrict uploads to only trusted file formats.",
            "reference": "https://owasp.org/www-community/vulnerabilities/File_Upload_Security_Best_Practices"
        },
        "tool": "ClamAV"
    },

    {
        "id": "FUNS:FUNS:2021",
        "title": "File Upload - No Size Restriction",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-400",
            "owasp_category": "A4 - Insecure Direct Object Reference"
        },
        "details": {
            "description": "No size restriction on file uploads can allow attackers to upload excessively large files that may cause Denial of Service (DoS) attacks.",
            "impact": "Large file uploads can overwhelm the server, exhaust storage resources, and degrade application performance.",
            "recommendations": "Set reasonable file size limits for all uploads and enforce them both client-side and server-side.",
            "reference": "https://owasp.org/www-community/vulnerabilities/File_Upload_Security_Best_Practices"
        },
        "tool": "OWASP ZAP"
    },

    {
        "id": "FUNB:FUNB:2021",
        "title": "File Upload - Null Byte",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.8,
            "cwe_id": "CWE-434",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Null byte injection occurs when a file upload process incorrectly handles null byte characters, potentially bypassing file type validation.",
            "impact": "This can lead to the upload of files with dangerous extensions or executable code that can be run on the server.",
            "recommendations": "Ensure that input sanitization and file extension checking are robust to prevent null byte injection.",
            "reference": "https://owasp.org/www-community/vulnerabilities/File_Upload_Security_Best_Practices"
        },
        "tool": "OWASP ZAP"
    },

    {
        "id": "FUSB:FUSB:2021",
        "title": "File Upload - Security Bypass",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-434",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Security bypass vulnerabilities occur when attackers can upload files with unauthorized extensions or content, leading to the execution of malicious code.",
            "impact": "Exploiting this vulnerability could lead to remote code execution, data breaches, or system compromise.",
            "recommendations": "Validate all uploaded files for content, file type, and extension. Employ anti-virus scans and restrict file types allowed for upload.",
            "reference": "https://owasp.org/www-community/vulnerabilities/File_Upload_Security_Best_Practices"
        },
        "tool": "ClamAV"
    },

    {
        "id": "FI:FI:2021",
        "title": "Functionality Issue",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 5.5,
            "cwe_id": "CWE-841",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "Functionality issues occur when an application's features do not behave as expected, creating a potential vulnerability.",
            "impact": "These issues can affect the integrity of the system, leading to unexpected behavior, crashes, or potential vulnerabilities.",
            "recommendations": "Ensure proper testing and validation of all application features and maintain a clear design specification.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Functionality_Issues"
        },
        "tool": "Manual Testing"
    },
    {
        "id": "HS:HS:2021",
        "title": "Hardcoded Secret",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.8,
            "cwe_id": "CWE-798",
            "owasp_category": "A3 - Sensitive Data Exposure"
        },
        "details": {
            "description": "Hardcoded secrets refer to sensitive credentials such as API keys, passwords, or other secrets embedded directly in the application's source code or configuration files.",
            "impact": "Exposing hardcoded secrets can lead to unauthorized access, data breaches, and compromise of the application and its infrastructure.",
            "recommendations": "Avoid hardcoding secrets. Use environment variables or secret management tools to store sensitive information securely.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
        },
        "tool": "GitLeaks"
    },
    {
        "id": "HPP:HPP:2021",
        "title": "HTTP Parameter Pollution",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.5,
            "cwe_id": "CWE-79",
            "owasp_category": "A9 - Using Components with Known Vulnerabilities"
        },
        "details": {
            "description": "HTTP Parameter Pollution (HPP) occurs when attackers manipulate the parameters of an HTTP request in order to confuse or bypass input validation mechanisms.",
            "impact": "This could allow attackers to manipulate backend behavior, leading to unintended actions, session hijacking, or potential cross-site scripting (XSS).",
            "recommendations": "Sanitize and validate input parameters, ensuring that only expected parameters are processed by the backend.",
            "reference": "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "HRS:HRS:2021",
        "title": "HTTP Request Smuggling",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-444",
            "owasp_category": "A9 - Security Misconfiguration"
        },
        "details": {
            "description": "HTTP request smuggling occurs when an attacker manipulates HTTP requests to create discrepancies between front-end and back-end systems, often bypassing security mechanisms.",
            "impact": "This can lead to unauthorized access, cache poisoning, or session hijacking, impacting the security and integrity of the web application.",
            "recommendations": "Ensure that the web server and proxy servers are properly configured to handle HTTP request parsing consistently. Implement strict validation of HTTP request headers.",
            "reference": "https://owasp.org/www-community/attacks/HTTP_Request_Smuggling"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "IDOR:IDOR:2021",
        "title": "IDOR (Insecure Direct Object Reference)",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.5,
            "cwe_id": "CWE-639",
            "owasp_category": "A4 - Insecure Direct Object Reference"
        },
        "details": {
            "description": "IDOR occurs when a user can access or modify resources they are not authorized to, by manipulating input parameters such as URLs or form data.",
            "impact": "Attackers can view or modify sensitive information, perform unauthorized actions, and escalate privileges.",
            "recommendations": "Implement proper authorization checks on every request to ensure users can only access resources they are authorized for.",
            "reference": "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "IEH:IEH:2021",
        "title": "Improper Error Handling",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-209",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "Improper error handling occurs when an application exposes too much information about its internal state, stack traces, or database errors in error messages.",
            "impact": "Attackers can gain insight into the internal workings of the application and potentially use that information to exploit vulnerabilities.",
            "recommendations": "Use generic error messages for users, and log detailed errors securely for internal use only.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Improper_Error_Handling"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "IIV:IIV:2021",
        "title": "Improper Input Validation",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-20",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Improper input validation occurs when user input is not properly checked for malicious or unexpected values, leading to security vulnerabilities.",
            "impact": "This can result in SQL injection, command injection, buffer overflows, or other attacks that exploit improperly validated input.",
            "recommendations": "Validate and sanitize all user inputs. Use whitelisting over blacklisting, and ensure input is properly escaped.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Improper_Input_Validation"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "ID:ID:2021",
        "title": "Information Disclosure",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.0,
            "cwe_id": "CWE-200",
            "owasp_category": "A3 - Sensitive Data Exposure"
        },
        "details": {
            "description": "Information disclosure happens when an application unintentionally exposes sensitive information to users or attackers, either through error messages or improperly configured settings.",
            "impact": "This could lead to attackers gathering information about the system, which could assist them in launching attacks such as social engineering or exploiting further vulnerabilities.",
            "recommendations": "Ensure sensitive information is never exposed in error messages or logs, and restrict access to sensitive data.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Information_Disclosure"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "IDV:IDV:2021",
        "title": "Information Disclosure (Hardcoded Version)",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 5.5,
            "cwe_id": "CWE-297",
            "owasp_category": "A9 - Insufficient Logging & Monitoring"
        },
        "details": {
            "description": "Information disclosure from hardcoded version numbers occurs when the application or its components expose version information that could help attackers identify vulnerable components.",
            "impact": "Knowing the version number can allow attackers to target specific vulnerabilities known to affect that version of the application or its dependencies.",
            "recommendations": "Remove version numbers or make them inaccessible to unauthorized users. Use version management systems to track versions securely.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Information_Disclosure_Version"
        },
        "tool": "GitHub Secret Scanning"
    },
    {
        "id": "IEQS:IEQS:2021",
        "title": "Information Exposure through Query Strings in URL",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-522",
            "owasp_category": "A3 - Sensitive Data Exposure"
        },
        "details": {
            "description": "Information exposure through query strings occurs when sensitive information such as user identifiers or session IDs is exposed in the URL query string.",
            "impact": "This can expose sensitive data to unauthorized users and can be easily intercepted in network traffic or browser history.",
            "recommendations": "Avoid placing sensitive information in the URL query string. Use POST methods or encrypt the data in the URL.",
            "reference": "https://owasp.org/www-community/attacks/Information_Exposure_Through_Query_Strings"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "CII:CII:2021",
        "title": "CSS Injection",
        "metadata": {
            "severity": "Low",
            "cvss_score": 4.5,
            "cwe_id": "CWE-79",
            "owasp_category": "A7 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "CSS Injection happens when an attacker injects malicious CSS code into a website, potentially leading to unintended styling or exposing sensitive information.",
            "impact": "CSS Injection can be used to alter the appearance of a website or to conduct phishing attacks.",
            "recommendations": "Sanitize and escape user inputs to avoid CSS injection. Apply the same precautions used for XSS to CSS input.",
            "reference": "https://owasp.org/www-community/attacks/CSS_Injection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "CVI:CVI:2021",
        "title": "CSV Injection",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-1339",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "CSV Injection occurs when user input is inserted into CSV files without proper sanitization, allowing malicious content to be executed upon opening the file.",
            "impact": "An attacker can craft malicious payloads that execute when the CSV file is opened, leading to potential data breaches or execution of arbitrary code.",
            "recommendations": "Ensure all user-supplied data is sanitized before inserting it into CSV files. Avoid allowing executable content like formulas.",
            "reference": "https://owasp.org/www-community/attacks/CSV_Injection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "HHI:HHI:2021",
        "title": "Host Header Injection",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.0,
            "cwe_id": "CWE-113",
            "owasp_category": "A10 - Insufficient Logging & Monitoring"
        },
        "details": {
            "description": "Host Header Injection happens when an attacker can modify the 'Host' header in an HTTP request, leading to various vulnerabilities like redirect attacks or cache poisoning.",
            "impact": "This can lead to security issues such as redirecting users to malicious sites, triggering unsafe requests or leaking sensitive information.",
            "recommendations": "Validate and sanitize the Host header to prevent unauthorized manipulations. Use strict control over domain titles and URLs.",
            "reference": "https://owasp.org/www-community/attacks/Host_Header_Injection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "HI:HI:2021",
        "title": "HTML Injection",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.5,
            "cwe_id": "CWE-79",
            "owasp_category": "A7 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "HTML Injection occurs when an attacker can inject malicious HTML code into a website's content, causing unintended behavior or exploitation of vulnerabilities.",
            "impact": "This can lead to phishing, malicious data injection, or even redirecting users to harmful websites.",
            "recommendations": "Sanitize user input to remove HTML tags, or use encoding techniques to prevent injection.",
            "reference": "https://owasp.org/www-community/attacks/HTML_Injection"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "IFI:IFI:2021",
        "title": "iFrame Injection",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-79",
            "owasp_category": "A7 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "iFrame Injection occurs when an attacker injects malicious iFrames into a website, potentially allowing unauthorized access or malicious content execution.",
            "impact": "This could lead to security breaches such as clickjacking, stealing of sensitive data, or phishing attacks.",
            "recommendations": "Validate and sanitize user input and content. Avoid allowing unsanitized HTML, and use sandboxing for embedded content.",
            "reference": "https://owasp.org/www-community/attacks/iFrame_Injection"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "LI:LI:2021",
        "title": "Link Injection",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-79",
            "owasp_category": "A7 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "Link Injection occurs when an attacker injects malicious URLs into a website, often with the aim of redirecting users to malicious sites or stealing their data.",
            "impact": "This could lead to phishing attacks or malicious redirection, compromising users' security and privacy.",
            "recommendations": "Sanitize all user-generated URLs, and implement a mechanism for only allowing trusted links.",
            "reference": "https://owasp.org/www-community/attacks/Link_Injection"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "OCI:OCI:2021",
        "title": "OS Command Injection",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-78",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "OS Command Injection occurs when an attacker can execute arbitrary OS commands through a vulnerable application, potentially gaining control over the system.",
            "impact": "This could allow attackers to execute arbitrary commands, gain unauthorized access, or even take full control of the system.",
            "recommendations": "Properly validate and sanitize all user input, avoid constructing OS commands with untrusted data, and use safe alternatives like parameterized commands.",
            "reference": "https://owasp.org/www-community/attacks/OS_Command_Injection"
        },
        "tool": "Metasploit"
    },
    {
        "id": "SSTI:SSTI:2021",
        "title": "Server-side Template Injection (SSTI)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-94",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Server-side Template Injection (SSTI) occurs when user input is injected into a template engine, allowing attackers to execute arbitrary code on the server.",
            "impact": "SSTI vulnerabilities can lead to remote code execution, data leakage, or full system compromise.",
            "recommendations": "Sanitize all user inputs that are processed by template engines, and ensure proper validation to avoid code injection vulnerabilities.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Server-side_Template_Injection"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "XI:XI:2021",
        "title": "XML Injection",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-643",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "XML Injection occurs when attackers inject malicious XML content into a web application, potentially causing XML parsing errors or exploitation of vulnerabilities.",
            "impact": "Attackers may gain access to sensitive data or inject malicious content that is processed by the application.",
            "recommendations": "Sanitize all XML input to ensure it is well-formed and properly validated before being processed by the application.",
            "reference": "https://owasp.org/www-community/vulnerabilities/XML_Injection"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "ICPF:ICPF:2021",
        "title": "Insecure Change Password Functionality",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-647",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Insecure change password functionality occurs when an application allows insecure or inadequate validation during the password change process.",
            "impact": "This could allow attackers to reset user passwords or escalate privileges if proper checks are not implemented.",
            "recommendations": "Implement secure password change functionality by verifying the user's identity with multi-factor authentication (MFA) and secure password validation.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Insecure_Change_Password_Functionality"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "ICSI:ICSI:2021",
        "title": "Insecure Communication (SSL Not Implemented)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 8.0,
            "cwe_id": "CWE-319",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Insecure Communication occurs when sensitive data is transmitted over insecure channels (e.g., HTTP instead of HTTPS), potentially allowing attackers to intercept the data.",
            "impact": "This can result in man-in-the-middle (MITM) attacks, leading to data leakage and unauthorized access to sensitive information.",
            "recommendations": "Always use HTTPS with SSL/TLS encryption for all sensitive communications to prevent interception by attackers.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "IFPD:IFPD:2021",
        "title": "Internal Full Path Disclosure",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-209",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "Internal Full Path Disclosure occurs when an application reveals full file paths in error messages, which can help attackers locate vulnerabilities.",
            "impact": "This can allow attackers to pinpoint vulnerabilities in the file system, leading to further exploitation.",
            "recommendations": "Ensure that detailed error messages are not displayed to the end user. Log errors without revealing full paths.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Path_Traversal"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "IID:IID:2021",
        "title": "Internal IP Disclosure",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.0,
            "cwe_id": "CWE-200",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "Internal IP Disclosure occurs when an application inadvertently reveals internal IP addresses, providing attackers with clues about the internal network infrastructure.",
            "impact": "This can lead to targeted attacks on internal resources or help attackers understand the internal network structure.",
            "recommendations": "Limit the exposure of internal IP addresses and ensure sensitive information is not exposed in error messages or logs.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Information_Disclosure"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "LFI:LFI:2021",
        "title": "Local File Inclusion (LFI)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-98",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Local File Inclusion (LFI) allows attackers to include files from the local server by manipulating user input, potentially leading to remote code execution.",
            "impact": "Attackers can access sensitive files, including system files, and could even execute arbitrary code if the server is misconfigured.",
            "recommendations": "Sanitize and validate user input to prevent directory traversal attacks. Use allow-lists for files that can be included.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Local_File_Inclusion"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MIA:MIA:2021",
        "title": "Method Interchange Attack (POST to GET)",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-1004",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "A Method Interchange Attack happens when an attacker changes the HTTP method (POST to GET) to bypass input validation or security controls.",
            "impact": "This can bypass security mechanisms like CSRF tokens or sensitive input handling, leading to unauthorized actions.",
            "recommendations": "Implement strict checks for the HTTP method used and ensure critical actions cannot be performed with alternative HTTP methods.",
            "reference": "https://owasp.org/www-community/attacks/HTTP_Method_Interchange"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "MCH:MCH:2021",
        "title": "Missing Cache-Control Header",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-524",
            "owasp_category": "A10 - Insufficient Logging & Monitoring"
        },
        "details": {
            "description": "Missing Cache-Control Header occurs when the 'Cache-Control' header is absent from HTTP responses, which can lead to sensitive data being cached by browsers or proxies.",
            "impact": "Sensitive information may be cached on the client or intermediary systems, potentially exposing it to unauthorized access.",
            "recommendations": "Ensure that sensitive pages have appropriate cache-control directives to prevent caching of sensitive content.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MCSPH:MCSPH:2021",
        "title": "Missing Content Security Policy (CSP) Header",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-1021",
            "owasp_category": "A3 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "The Missing Content Security Policy (CSP) Header occurs when the CSP header is not set, leaving web applications vulnerable to various attacks, including XSS.",
            "impact": "Attackers may be able to inject malicious scripts into pages, leading to cross-site scripting (XSS) attacks.",
            "recommendations": "Implement a Content Security Policy to restrict which resources can be loaded by the browser. Use 'default-src' to control the sources of all content.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A3_2017-Cross_Site_Scripting_XSS"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MEH:MEH:2021",
        "title": "Missing Expires Header",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-524",
            "owasp_category": "A10 - Insufficient Logging & Monitoring"
        },
        "details": {
            "description": "Missing Expires Header occurs when the 'Expires' HTTP header is not set, potentially allowing sensitive information to be cached by browsers or proxies.",
            "impact": "Sensitive data might be cached, making it accessible to unauthorized users even after the session has ended.",
            "recommendations": "Set the 'Expires' header to prevent caching of sensitive information and ensure it is no longer stored in the browser cache after a set period.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MHSTS:MHSTS:2021",
        "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-319",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "The Missing HTTP Strict-Transport-Security (HSTS) Header occurs when the 'Strict-Transport-Security' header is not set, leaving the site vulnerable to SSL stripping attacks.",
            "impact": "An attacker can perform a man-in-the-middle (MITM) attack and downgrade the connection from HTTPS to HTTP, intercepting sensitive information.",
            "recommendations": "Set the HSTS header to enforce HTTPS connections and prevent SSL stripping attacks. Use 'max-age' to specify the duration.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MPH:MPH:2021",
        "title": "Missing Permissions-Policy Header",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-942",
            "owasp_category": "A9 - Using Components with Known Vulnerabilities"
        },
        "details": {
            "description": "Missing Permissions-Policy Header occurs when the Permissions-Policy header is absent, leaving the web application vulnerable to unauthorized access of features like camera or microphone.",
            "impact": "Attackers could gain access to sensitive device features or trigger unwanted behaviors, such as accessing the user's camera or microphone.",
            "recommendations": "Set a Permissions-Policy header to restrict access to sensitive features in the browser.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MPH:MPH:2021",
        "title": "Missing Pragma Header",
        "metadata": {
            "severity": "Low",
            "cvss_score": 5.0,
            "cwe_id": "CWE-524",
            "owasp_category": "A10 - Insufficient Logging & Monitoring"
        },
        "details": {
            "description": "Missing Pragma Header occurs when the 'Pragma' header is not set, potentially affecting caching behavior and security.",
            "impact": "This can lead to caching sensitive information or improper cache handling in certain scenarios.",
            "recommendations": "Set the 'Pragma' header to control cache settings, particularly for sensitive pages.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MRPH:MRPH:2021",
        "title": "Missing Referrer-Policy Header",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-200",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "The Missing Referrer-Policy Header occurs when the 'Referrer-Policy' HTTP header is not set, potentially exposing sensitive information in referrer headers.",
            "impact": "This could reveal sensitive data in the 'Referer' header, such as user authentication tokens or session IDs, to unauthorized recipients.",
            "recommendations": "Set a Referrer-Policy header to control the amount of information sent with the Referer header across domains.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MXCTOH:MXCTOH:2021",
        "title": "Missing X-Content-Type-Options Header",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-116",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "The Missing X-Content-Type-Options Header occurs when the 'X-Content-Type-Options' HTTP header is not set, potentially allowing browsers to infer content types and execute malicious scripts.",
            "impact": "An attacker could exploit this to launch attacks, like drive-by downloads or cross-site scripting (XSS) attacks.",
            "recommendations": "Always set the 'X-Content-Type-Options' header to 'nosniff' to prevent browsers from attempting to sniff content types.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MXFO:MXFO:2021",
        "title": "Missing X-Frame-Options Header",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-1021",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "The Missing X-Frame-Options Header vulnerability arises when the 'X-Frame-Options' HTTP header is not set, allowing the application to be embedded in an iframe on other websites.",
            "impact": "This could allow clickjacking attacks where a malicious site overlays a hidden iframe to trick users into interacting with unintended actions.",
            "recommendations": "Set the 'X-Frame-Options' header to 'DENY' or 'SAMEORIGIN' to prevent the site from being embedded in iframes.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MXPCDPH:MXPCDPH:2021",
        "title": "Missing X-Permitted-Cross-Domain-Policies Header",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-16",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "The Missing X-Permitted-Cross-Domain-Policies Header vulnerability occurs when the 'X-Permitted-Cross-Domain-Policies' HTTP header is not set, which could allow Flash or other content to interact with external domains.",
            "impact": "This could lead to attackers gaining access to sensitive information or executing unauthorized actions.",
            "recommendations": "Set the 'X-Permitted-Cross-Domain-Policies' header to 'none' to prevent cross-domain requests from untrusted domains.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Permitted-Cross-Domain-Policies"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "MXXSP: MXXSP:2021",
        "title": "Missing X-XSS-Protection Header",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-79",
            "owasp_category": "A7 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "The Missing X-XSS-Protection Header occurs when the 'X-XSS-Protection' HTTP header is not set, leaving the web application vulnerable to reflected XSS attacks.",
            "impact": "This can allow attackers to inject malicious scripts into the page, which can steal sensitive user data or perform actions on behalf of the user.",
            "recommendations": "Enable the 'X-XSS-Protection' header with a value of '1; mode=block' to mitigate reflected XSS attacks.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "OBF:OBF:2021",
        "title": "OTP Brute Force",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.5,
            "cwe_id": "CWE-770",
            "owasp_category": "A8 - Insecure Deserialization"
        },
        "details": {
            "description": "OTP Brute Force occurs when the system allows attackers to try many One-Time Passwords (OTPs) to guess the correct one, potentially bypassing authentication mechanisms.",
            "impact": "An attacker can use brute force techniques to guess the correct OTP, which could grant unauthorized access to sensitive resources.",
            "recommendations": "Implement rate limiting and account lockout mechanisms to prevent multiple failed OTP attempts. Consider using time-based OTPs with additional security features.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Brute_Force_Attack"
        },
        "tool": "Hydra"
    },
    {
        "id": "OOV:OOV:2021",
        "title": "Out-Of-Date Component Version",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-1104",
            "owasp_category": "A9 - Using Components with Known Vulnerabilities"
        },
        "details": {
            "description": "Out-Of-Date Component Version occurs when the application uses outdated libraries or components with known security vulnerabilities.",
            "impact": "Using outdated components increases the risk of exploitation by attackers who are aware of these vulnerabilities.",
            "recommendations": "Ensure that all third-party components are up-to-date and patched regularly. Use tools to monitor known vulnerabilities in components.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Outdated_Components"
        },
        "tool": "OWASP Dependency-Check"
    },
    {
        "id": "PT:PT:2021",
        "title": "Parameter Tampering",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-20",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Parameter Tampering occurs when an attacker manipulates URL parameters, cookies, or other input values to modify application behavior.",
            "impact": "Attackers can bypass access controls, manipulate the application's state, or gain unauthorized access to sensitive data.",
            "recommendations": "Validate and sanitize all user inputs, and avoid relying solely on client-side data for sensitive decisions.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Parameter_Tampering"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "PRR:PRR:2021",
        "title": "Password Revealed in Response",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-257",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Password Revealed in Response occurs when the application sends passwords in cleartext or an easily accessible format in HTTP responses.",
            "impact": "Attackers can intercept sensitive data such as passwords in transit, leading to account takeovers or data leaks.",
            "recommendations": "Ensure passwords are never sent in responses or logs. Use secure password storage mechanisms like bcrypt and ensure proper encryption for sensitive data in transit.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Password_Leak"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "PBF: PBF:2021",
        "title": "Possible Brute Force Attack – CAPTCHA Not Found",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-307",
            "owasp_category": "A7 - Cross-Site Scripting (XSS)"
        },
        "details": {
            "description": "Possible Brute Force Attack – CAPTCHA Not Found occurs when there is no CAPTCHA implemented to prevent automated attacks like brute force.",
            "impact": "Without CAPTCHA, attackers can perform brute-force attacks on login forms or other sensitive endpoints.",
            "recommendations": "Implement CAPTCHA or other rate-limiting techniques to prevent automated brute-force attacks.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Brute_Force_Attack"
        },
        "tool": "Hydra"
    },
    {
        "id": "PE:PE:2021",
        "title": "Privilege Escalation",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.5,
            "cwe_id": "CWE-732",
            "owasp_category": "A4 - Insecure Design"
        },
        "details": {
            "description": "Privilege Escalation occurs when an attacker gains elevated privileges beyond what is intended, potentially accessing restricted parts of the system.",
            "impact": "An attacker can escalate their privileges to gain unauthorized access to sensitive data or perform unauthorized actions.",
            "recommendations": "Implement strict access control mechanisms and ensure users can only access resources that are appropriate for their privilege level.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Privilege_Escalation"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "RC:RC:2021",
        "title": "Race Condition",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.5,
            "cwe_id": "CWE-362",
            "owasp_category": "A4 - Insecure Design"
        },
        "details": {
            "description": "A Race Condition occurs when the timing of an event impacts the system’s behavior, leading to inconsistent states or vulnerabilities.",
            "impact": "An attacker could exploit this to cause inconsistent states, leading to unauthorized actions or access to sensitive data.",
            "recommendations": "Ensure proper synchronization in the system’s processes and use locking mechanisms where necessary to prevent timing-based vulnerabilities.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Race_Condition"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "RLNID:RLNID:2021",
        "title": "Rate Limit Not Implemented",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-770",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Rate Limit Not Implemented occurs when the application does not enforce rate limits on critical endpoints, such as login forms or API calls.",
            "impact": "Without rate limiting, an attacker could perform brute force or denial of service attacks by flooding the system with requests.",
            "recommendations": "Implement rate limiting on critical endpoints to reduce the risk of brute force and DoS attacks.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Rate_Limiting"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "RCE:RCE:2021",
        "title": "Remote Code Execution (RCE)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.8,
            "cwe_id": "CWE-94",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Remote Code Execution (RCE) occurs when an attacker is able to execute arbitrary code on a remote server or system.",
            "impact": "An attacker can exploit RCE vulnerabilities to fully compromise the affected server and execute arbitrary commands, potentially causing severe damage.",
            "recommendations": "Sanitize and validate all inputs to prevent code injection and use secure coding practices to avoid creating exploitable endpoints.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Remote_Code_Execution"
        },
        "tool": "Metasploit"
    },
    {
        "id": "RFI:RFI:2021",
        "title": "Remote File Inclusion (RFI)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-98",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Remote File Inclusion (RFI) occurs when an attacker is able to include a file from a remote server, potentially allowing them to execute malicious code on the server.",
            "impact": "An attacker could use RFI to include malicious files or scripts, leading to code execution and potentially full server compromise.",
            "recommendations": "Ensure that only trusted files are included and sanitize all file paths or URLs before including them. Disable the ability to include files from remote sources.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Remote_File_Inclusion"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "2FANID:2FANID:2021",
        "title": "Second Factor Authentication (2FA) Not Implemented",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.5,
            "cwe_id": "CWE-287",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Second Factor Authentication (2FA) Not Implemented occurs when an application relies solely on passwords for authentication, without an additional layer of security such as two-factor authentication.",
            "impact": "Without 2FA, attackers who compromise a user’s password can gain unauthorized access to sensitive resources.",
            "recommendations": "Implement 2FA across all critical application areas to improve the security of user authentication and mitigate password theft risks.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Second_Factor_Authentication"
        },
        "tool": "Authy"
    },
    {
        "id": "SM:SM:2021",
        "title": "Security Misconfiguration",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-16",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Security Misconfiguration occurs when an application is deployed with insecure default configurations or improper security settings.",
            "impact": "Misconfigurations can lead to various vulnerabilities such as open ports, exposed sensitive data, or weak authentication mechanisms.",
            "recommendations": "Review and implement secure configuration settings during development and deployment. Regularly audit configurations for security flaws.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Security_Misconfiguration"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "SFD:SFD:2021",
        "title": "Sensitive Files Disclosure",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-200",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Sensitive Files Disclosure occurs when an application accidentally exposes sensitive files or information, such as configuration files or databases, to unauthorized users.",
            "impact": "Attackers can access sensitive information such as user data, passwords, or cryptographic keys, leading to data breaches.",
            "recommendations": "Ensure that sensitive files are properly protected with access controls and are not publicly accessible. Use file scanning to identify and secure such files.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Sensitive_Files_Disclosure"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "SIDR:SIDR:2021",
        "title": "Sensitive Information Disclosed in Response",
        "metadata": {
            "severity": "High",
            "cvss_score": 9.0,
            "cwe_id": "CWE-200",
            "owasp_category": "A3 - Sensitive Data Exposure"
        },
        "details": {
            "description": "Sensitive Information Disclosed in Response occurs when the application exposes sensitive data, such as credit card numbers or passwords, in HTTP responses.",
            "impact": "Sensitive information leakage could lead to identity theft or financial loss for users, and legal/regulatory consequences for the organization.",
            "recommendations": "Ensure that sensitive information is never exposed in responses. Use proper encryption and masking mechanisms for sensitive data.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Sensitive_Information_Disclosed_in_Response"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "SPD:SPD:2021",
        "title": "Sensitive Page Disclosure",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-200",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Sensitive Page Disclosure occurs when an application unintentionally exposes pages with sensitive data, such as admin pages or user profile pages, to unauthorized users.",
            "impact": "This can lead to unauthorized access to sensitive user data or privileged areas of the application.",
            "recommendations": "Ensure that sensitive pages are protected by proper access controls and are not accessible to unauthorized users.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Sensitive_Page_Disclosure"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "SRT403:SRT403:2021",
        "title": "Server Returns 403 Forbidden Response or Error",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-307",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "A 403 Forbidden response indicates that the server understands the request but refuses to authorize it. This can be caused by misconfigurations or improper access controls.",
            "impact": "Unauthorized users may gain insights into the server's structure, or unauthorized access may be granted unintentionally.",
            "recommendations": "Ensure proper access controls and authentication are in place. Avoid disclosing sensitive details in error responses.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Server_Returns_403_Forbidden_Response_or_Error"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "SSVP:SSVP:2021",
        "title": "Server-Side Validations are not in Place",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 8.5,
            "cwe_id": "CWE-20",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Server-side validation ensures that incoming data meets the security standards of the server. Lack of validation can allow malicious data to compromise the server.",
            "impact": "Without server-side validation, attackers can send malicious data that could exploit vulnerabilities in the application, leading to data corruption or unauthorized access.",
            "recommendations": "Implement strong server-side validation mechanisms to verify input data and protect against attacks such as SQL injection and cross-site scripting (XSS).",
            "reference": "https://owasp.org/www-community/vulnerabilities/Server-Side_Validation"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "SCHA:SCHA:2021",
        "title": "Session Cookie HttpOnly Attribute Not Set",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-200",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "The HttpOnly attribute prevents client-side scripts from accessing session cookies, which protects against cross-site scripting (XSS) attacks.",
            "impact": "If this attribute is not set, attackers can steal session cookies via XSS, leading to session hijacking and unauthorized access.",
            "recommendations": "Always set the HttpOnly attribute on session cookies to protect them from being accessed by malicious JavaScript.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Session_Cookie_HttpOnly_Attribute_Not_Set"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "SCSM:SCSM:2021",
        "title": "Session Cookie SameSite Attribute Not Set",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-693",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "The SameSite attribute on session cookies ensures that cookies are only sent for same-site requests, mitigating cross-site request forgery (CSRF) attacks.",
            "impact": "Without this attribute, cookies could be sent with cross-site requests, making the application vulnerable to CSRF attacks.",
            "recommendations": "Set the SameSite attribute to 'Strict' or 'Lax' for session cookies to prevent them from being sent in cross-site requests.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Session_Cookie_SameSite_Attribute_Not_Set"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "SCSA:SCSA:2021",
        "title": "Session Cookie Secure Attribute Not Set",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-319",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "The Secure attribute ensures that cookies are only sent over secure (HTTPS) connections, protecting them from being transmitted over unencrypted HTTP connections.",
            "impact": "If the Secure attribute is not set, session cookies can be exposed to attackers on an unencrypted HTTP connection, leading to session hijacking.",
            "recommendations": "Always set the Secure attribute on session cookies to ensure they are transmitted only over HTTPS.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Session_Cookie_Secure_Attribute_Not_Set"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "SF:SF:2021",
        "title": "Session Fixation",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-384",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Session Fixation allows an attacker to set a user's session ID before the user logs in, enabling the attacker to hijack the session once the user logs in.",
            "impact": "An attacker can gain unauthorized access to a user's session and perform actions on their behalf.",
            "recommendations": "Generate a new session ID after successful login and ensure that session IDs cannot be fixed by attackers.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Session_Fixation"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "SIR:SIR:2021",
        "title": "Session ID Remains Constant Before Login and After Logout",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-384",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Session IDs should be reset after login and logout to prevent attackers from using stale session IDs to impersonate a user.",
            "impact": "If session IDs remain constant before and after login/logout, attackers can hijack a session or reuse a session ID to gain unauthorized access.",
            "recommendations": "Ensure that session IDs are regenerated during login and logout processes, preventing session hijacking and reuse.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Session_ID_Remains_Constant"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "STI:STI:2021",
        "title": "Session Timeout is High or Not Implemented",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.5,
            "cwe_id": "CWE-613",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Session timeouts should be implemented to automatically log out inactive users to protect against session hijacking.",
            "impact": "If session timeouts are too long or not set, attackers may hijack inactive sessions and perform unauthorized actions.",
            "recommendations": "Set appropriate session timeouts and log users out after a period of inactivity to protect against session hijacking.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Session_Timeout_is_High_or_Not_Implemented"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "SLE:SLE:2021",
        "title": "Simultaneous Login Enabled (Concurrent Login Allowed)",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-287",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Allowing multiple sessions for the same user increases the attack surface and makes it easier for attackers to hijack sessions.",
            "impact": "Simultaneous logins may lead to unauthorized access if attackers hijack a session and gain access to a user’s account from a different location.",
            "recommendations": "Consider implementing limits on simultaneous logins or require users to manually terminate previous sessions before logging in from another device.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Simultaneous_Login_Enabled"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "SIB:SB:2021",
        "title": "SQL Injection (Boolean-based Blind SQL Injection)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-89",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Boolean-based Blind SQL Injection occurs when an attacker is able to inject malicious SQL queries into an application's input fields that rely on logical conditions to retrieve data.",
            "impact": "Attackers can exploit this to manipulate the database, retrieve sensitive information, or perform unauthorized actions.",
            "recommendations": "Use parameterized queries or prepared statements to prevent SQL injection and ensure input validation and sanitization.",
            "reference": "https://owasp.org/www-community/vulnerabilities/SQL_Injection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "SIEBS:2021",
        "title": "SQL Injection (Error-Based SQL Injection)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-89",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Error-based SQL injection is a type of SQL injection where the attacker is able to trigger detailed error messages from the database, which can help in further exploitation.",
            "impact": "Attackers can gain access to the database structure, retrieve sensitive information, and potentially execute harmful SQL commands.",
            "recommendations": "Use parameterized queries or prepared statements to prevent SQL injection. Avoid exposing detailed database error messages to users.",
            "reference": "https://owasp.org/www-community/vulnerabilities/SQL_Injection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "SITB:2021",
        "title": "SQL Injection (Time-Based Blind SQL Injection)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-89",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Time-based blind SQL injection occurs when the attacker makes the database perform an operation that delays the response to verify if their query is valid based on the response time.",
            "impact": "Attackers can infer database information by observing delays and manipulate the database, leading to unauthorized access or data retrieval.",
            "recommendations": "Use parameterized queries, prepared statements, and input sanitization to prevent SQL injection.",
            "reference": "https://owasp.org/www-community/vulnerabilities/SQL_Injection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "SIUB:2021",
        "title": "SQL Injection (Union-Based SQL Injection)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-89",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Union-based SQL injection occurs when an attacker can use the UNION SQL operator to combine results from two or more SELECT queries and extract sensitive data from the database.",
            "impact": "Attackers can retrieve sensitive data, manipulate database queries, and potentially execute malicious commands.",
            "recommendations": "Implement parameterized queries, input validation, and use stored procedures to prevent this type of SQL injection.",
            "reference": "https://owasp.org/www-community/vulnerabilities/SQL_Injection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "SWDA:2021",
        "title": "SQL Wildcard Attack",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-89",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "SQL wildcard attacks leverage the use of SQL wildcards ('%' or '_') in query input fields, which can lead to unauthorized data access or result in unintended query behavior.",
            "impact": "Attackers can modify or manipulate queries to bypass security controls and access sensitive information.",
            "recommendations": "Use parameterized queries to prevent wildcard manipulation and ensure proper input sanitization.",
            "reference": "https://owasp.org/www-community/vulnerabilities/SQL_Injection"
        },
        "tool": "SQLmap"
    },
    {
        "id": "SSLV2PD:2021",
        "title": "SSL Version 2.0 Protocol Detection",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-323",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "SSL version 2.0 is an outdated protocol with known security vulnerabilities, and its use can expose sensitive data to potential attackers.",
            "impact": "Using SSL v2.0 puts encrypted traffic at risk, allowing attackers to intercept and manipulate communication.",
            "recommendations": "Disable SSL v2.0 on your server and configure it to only support stronger versions like TLS 1.2 or higher.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A6-Security-Misconfiguration"
        },
        "tool": "OpenSSL"
    },
    {
        "id": "SSLV3PD:2021",
        "title": "SSL Version 3.0 Protocol Detection",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-323",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "SSL version 3.0 is deprecated and vulnerable to attacks like POODLE. Its usage exposes the application to various risks.",
            "impact": "Attackers can exploit SSLv3 vulnerabilities to decrypt and manipulate sensitive data transmitted over the network.",
            "recommendations": "Disable SSL 3.0 and configure your server to support only secure versions of TLS (1.2 or 1.3).",
            "reference": "https://owasp.org/www-project-top-ten/2017/A6-Security-Misconfiguration"
        },
        "tool": "OpenSSL"
    },
    {
        "id": "SSRF:2021",
        "title": "Server-Side Request Forgery (SSRF)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-918",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "SSRF allows attackers to send requests from the server to internal resources, potentially accessing restricted or sensitive data.",
            "impact": "An attacker can make arbitrary requests, leading to data leakage or other security compromises in internal networks.",
            "recommendations": "Implement strict input validation, allowlist internal endpoints, and restrict access to sensitive internal resources.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Server-Side_Request_Forgery"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "STE:2021",
        "title": "Stack Trace Error",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-209",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Stack trace errors reveal detailed information about the server environment, application code, and database, which can be exploited by attackers.",
            "impact": "Sensitive information from stack traces can aid attackers in launching targeted attacks, such as SQL injection or path traversal.",
            "recommendations": "Disable stack trace output in production environments and ensure that error handling is generic and does not reveal system internals.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Stack_Trace_Error"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "TSPAS:2021",
        "title": "Test Script Page Available on Server",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.0,
            "cwe_id": "CWE-502",
            "owasp_category": "A5 - Security Misconfiguration"
        },
        "details": {
            "description": "Test script pages left on the server can expose sensitive information about the application’s environment and codebase.",
            "impact": "Attackers can use these test pages to gather intelligence about the server and exploit vulnerabilities.",
            "recommendations": "Remove all test scripts and unnecessary files from production environments to minimize exposure.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Test_Script_Page_Available_on_Server"
        },
        "tool": "Nmap"
    },
    {
        "id": "TLSV1PD:2021",
        "title": "TLS Version 1.0 Protocol Detection",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-323",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "TLS 1.0 is considered weak due to known vulnerabilities and should not be used for secure communication.",
            "impact": "TLS 1.0 is vulnerable to multiple attack vectors, including POODLE, and allows attackers to downgrade the connection to a less secure protocol.",
            "recommendations": "Disable TLS 1.0 and configure the server to support only stronger protocols like TLS 1.2 or 1.3.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A6-Security-Misconfiguration"
        },
        "tool": "OpenSSL"
    },
    {
        "id": "TLSV1.1PD:2021",
        "title": "TLS Version 1.1 Protocol Detection",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-323",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "TLS 1.1 is an outdated protocol with known vulnerabilities, and it should not be used for secure communications.",
            "impact": "Using TLS 1.1 exposes encrypted traffic to potential attacks like POODLE, weakening overall communication security.",
            "recommendations": "Disable TLS 1.1 and configure your server to support only more secure versions like TLS 1.2 or TLS 1.3.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A6-Security-Misconfiguration"
        },
        "tool": "OpenSSL"
    },
    {
        "id": "UFL:2021",
        "title": "Unrestricted Field Length",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.5,
            "cwe_id": "CWE-400",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "Unrestricted field length can result in buffer overflow, leading to potential memory corruption or denial of service.",
            "impact": "Excessive input length in certain fields can cause buffer overflows, allowing attackers to execute arbitrary code or crash the application.",
            "recommendations": "Implement input length validation and ensure all fields have proper length restrictions.",
            "reference": "https://owasp.org/www-community/vulnerabilities/Unrestricted_Field_Length"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "UHEM:2021",
        "title": "Unwanted HTTP Methods Enabled",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.0,
            "cwe_id": "CWE-0",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "Unwanted HTTP methods (like DELETE or TRACE) being enabled on a web server can increase the attack surface.",
            "impact": "Attackers may exploit unnecessary HTTP methods to perform unauthorized actions like deleting files or tracing requests.",
            "recommendations": "Restrict HTTP methods to only the ones necessary for the application, such as GET and POST.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A6-Security-Misconfiguration"
        },
        "tool": "Nmap"
    },
    {
        "id": "USNP:2021",
        "title": "User Can Set New Password as Old Password",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.0,
            "cwe_id": "CWE-640",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "Allowing a user to set their new password to be the same as their old one defeats the purpose of changing a password and can enable account recovery circumvention.",
            "impact": "If users can reset their password to the same value, attackers may bypass password change controls and access accounts.",
            "recommendations": "Ensure that the new password cannot be the same as the old password during password resets.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A2-Broken-Authentication"
        },
        "tool": "Custom"
    },
    {
        "id": "UE:2021",
        "title": "User Enumeration",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.0,
            "cwe_id": "CWE-204",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "User enumeration happens when an attacker can determine whether a username exists or not based on the application's response behavior.",
            "impact": "Attackers can leverage user enumeration to find valid usernames for brute force or credential stuffing attacks.",
            "recommendations": "Ensure consistent error messages for both valid and invalid usernames to prevent enumeration attacks.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A2-Broken-Authentication"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "VD:2021",
        "title": "Version Disclosure",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 5.5,
            "cwe_id": "CWE-200",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "Version disclosure reveals the software version being used, which can provide attackers with information about known vulnerabilities.",
            "impact": "Attackers can exploit vulnerabilities specific to the revealed version, potentially leading to successful attacks.",
            "recommendations": "Disable version disclosure in HTTP headers and error messages, or provide generic versioning information.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A6-Security-Misconfiguration"
        },
        "tool": "Nmap"
    },
    {
        "id": "VCU:2021",
        "title": "Vulnerable Component Used",
        "metadata": {
            "severity": "High",
            "cvss_score": 8.0,
            "cwe_id": "CWE-1104",
            "owasp_category": "A9 - Using Components with Known Vulnerabilities"
        },
        "details": {
            "description": "Using outdated or vulnerable components (e.g., libraries, frameworks, etc.) exposes the application to various attack vectors.",
            "impact": "Known vulnerabilities in third-party components can be exploited, potentially compromising the application's security.",
            "recommendations": "Regularly update and patch components, and use a tool to monitor known vulnerabilities in dependencies.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A9-Using-Components-with-Known-Vulnerabilities"
        },
        "tool": "OWASP Dependency-Check"
    },
    {
        "id": "WCUE:2021",
        "title": "Weak Ciphers Enabled",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-326",
            "owasp_category": "A6 - Security Misconfiguration"
        },
        "details": {
            "description": "Weak ciphers, such as those using outdated encryption algorithms (e.g., RC4), can easily be broken by attackers.",
            "impact": "Data encrypted with weak ciphers can be intercepted and decrypted, allowing attackers to access sensitive information.",
            "recommendations": "Use strong ciphers (e.g., AES-256) and configure your server to only support secure cryptographic protocols like TLS 1.2 or 1.3.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A6-Security-Misconfiguration"
        },
        "tool": "SSL Labs"
    },
    {
        "id": "WEU:2021",
        "title": "Weak Encoding is Used",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.5,
            "cwe_id": "CWE-327",
            "owasp_category": "A9 - Using Components with Known Vulnerabilities"
        },
        "details": {
            "description": "Weak encoding practices (e.g., base64) may expose sensitive data to attackers, allowing them to decode and manipulate the information.",
            "impact": "Sensitive data can be decoded and exposed if weak encoding techniques are used.",
            "recommendations": "Use secure encryption techniques instead of weak encoding methods for sensitive data.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A9-Using-Components-with-Known-Vulnerabilities"
        },
        "tool": "Custom"
    },
    {
        "id": "WPP:2021",
        "title": "Weak Password Policy",
        "metadata": {
            "severity": "High",
            "cvss_score": 7.5,
            "cwe_id": "CWE-521",
            "owasp_category": "A2 - Broken Authentication"
        },
        "details": {
            "description": "A weak password policy allows users to choose easily guessable passwords, which can be exploited in brute force or dictionary attacks.",
            "impact": "Weak passwords make it easier for attackers to gain unauthorized access to user accounts.",
            "recommendations": "Implement a strong password policy that enforces the use of complex passwords with a minimum length and special characters.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A2-Broken-Authentication"
        },
        "tool": "OWASP ZAP"
    },
    {
        "id": "XXE:2021",
        "title": "XML External Entity (XXE)",
        "metadata": {
            "severity": "Critical",
            "cvss_score": 9.0,
            "cwe_id": "CWE-611",
            "owasp_category": "A1 - Injection"
        },
        "details": {
            "description": "XML External Entity (XXE) injection occurs when an XML parser processes untrusted input containing references to external entities.",
            "impact": "XXE attacks can lead to information disclosure, denial of service, and remote code execution.",
            "recommendations": "Disable external entity processing in XML parsers and validate XML input rigorously.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A1-Injection"
        },
        "tool": "Burp Suite"
    },
    {
        "id": "XMLRPC:2021",
        "title": "XMLRPC.php File Found",
        "metadata": {
            "severity": "Medium",
            "cvss_score": 6.5,
            "cwe_id": "CWE-0",
            "owasp_category": "A7 - Cross-Site Scripting"
        },
        "details": {
            "description": "The XMLRPC.php file is a common vector for WordPress-based attacks, as it allows remote procedure calls that can be abused by attackers.",
            "impact": "If left exposed, XMLRPC.php can facilitate brute force attacks or unauthorized remote access to the system.",
            "recommendations": "Disable or restrict access to XMLRPC.php, or remove it if not required by the application.",
            "reference": "https://owasp.org/www-project-top-ten/2017/A7-Cross-Site-Scripting"
        },
        "tool": "Nmap"
    }
]

export const sortedVulns = vulns.sort((a, b) => a.title.localeCompare(b.title));