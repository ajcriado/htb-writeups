## Scope

The scope of this assessment is as follows:

    - www.trilocor.local, any identified *.trilocor.local subdomain, and any open web server ports discovered on the "Entry Point" IP address that will become visible upon pressing "SPAWN INSTANCE" (Step 2 below).
    - Scanning any other IP in the Entry Point's network is NOT allowed!
    - Multiple different subdomains exist on the entry point host

    URL/CIDR Range 	    Description
    trilocor.local 	    Main Trilocor website
    172.16.139.0/24 	Internal network subnet
    172.16.210.0/24 	Internal network subnet

## Rules of Engagement

The following types of findings are in-scope for this penetration test assessment:

    - Sensitive or personally identifiable information disclosure
    - Remote Code Execution (RCE)
    - Arbitrary file upload
    - Authentication or authorization flaws, such as insecure direct object references (IDOR) and authentication bypasses
    - All forms of injection vulnerabilities
    - Directory traversal
    - Local file read
    - Significant security misconfigurations and business logic flaws
    - Exposed credentials that could be leveraged to gain further access
    - Windows and Linux local privilege escalation vulnerabilities
    - Vulnerable services and applications
    - Active Directory vulnerabilities & misconfigurations

The following types of activities are considered out-of-scope for this penetration test:

    - Scanning and assessing any other IP in the entry point's network or hosts that do not fall within the in-scope internal subnets
    - Physical attacks against Trilocor properties
    - Unverified scanner output
    - Any vulnerabilities identified through DDoS or spam attacks
    - Self-XSS
    - Login/logout CSRF
    - Issues with SSL certificates, open ports, TLS versions, or missing HTTP response headers
    - Vulnerabilities in third-party libraries unless they can be leveraged to significantly impact the target
    - Any theoretical attacks or attacks that require significant user interaction or low risk
    - Phishing or social engineering attacks against Trilocor employees or contractors

## Connectivity Prerequisites

If you are using your own attacking virtual machine to connect to the exam lab's VPN, then you can test your connectivity by adding an entry regarding trilocor.local in your virtual machine's hosts file and browsing http://trilocor.local.

## Exam Objectives

To be awarded the HTB Certified Penetration Testing Specialist (CPTS) certification, you must:

    - Obtain a minimum of 85 points by submitting 12/14 of the flags listed below AND
    - Compose and submit a commercial-grade report including all identified vulnerabilities, evidence of successful exploitation (in a step-by-step manner), and remediation advice based on the provided report template.

## Flag Locations

    - USER flags can be found at /home/<user>/flag.txt on Linux hosts and at C:\Users\<user>\Desktop\flag.txt on Windows hosts
    - ROOT flags can be found at /root/flag.txt on Linux hosts and at C:\Users\Administrator\Desktop\flag.txt on Windows hosts
