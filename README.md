# VulnUserManager - Intentionally Vulnerable Application

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational and testing purposes. DO NOT deploy to production or expose to the internet!**

## Overview

VulnUserManager is a deliberately vulnerable Spring Boot application designed for:
- Static Application Security Testing (SAST) tool evaluation
- Security training and education
- Demonstrating common CWE (Common Weakness Enumeration) vulnerabilities
- Testing security scanning tools like SonarQube

## Technology Stack

- **Java**: 17
- **Spring Boot**: 3.2.0
- **Database**: H2 (in-memory)
- **Build Tool**: Maven
- **Security**: Spring Security (intentionally misconfigured)

## Running the Application

### Prerequisites
- Java 17 or higher
- Maven 3.6+

### Build and Run

```bash
# Build the application
mvn clean package

# Run the application
mvn spring-boot:run

# Or run the JAR directly
java -jar target/vuln-user-manager-1.0.0-SNAPSHOT.jar
```

The application will start on `http://localhost:8080`

## Vulnerable Endpoints

### CWE-94: Code Injection
**POST** `/api/eval-code`
- Executes arbitrary JavaScript code using Nashorn script engine
- No input validation or sandboxing
- Example payload:
```json
{
  "script": "java.lang.System.getProperty('user.name')"
}
```

### CWE-20: Improper Input Validation
**POST** `/api/register`
- Accepts null or empty username/password
- No validation on user registration
- Example payload:
```json
{
  "username": "",
  "password": "",
  "email": "test@test.com",
  "role": "USER"
}
```

### CWE-77: OS Command Injection
**POST** `/api/run-command`
- Executes system commands using ProcessBuilder
- Uses `cmd.split(" ")` without sanitization
- Example payload:
```json
{
  "cmd": "ls -la"
}
```

**POST** `/api/system-ping` (existing)
- Executes ping command with Runtime.exec()
- Query param: `host`

### CWE-287: Improper Authentication
- Plain-text password storage in User entity
- NoOpPasswordEncoder (no BCrypt)
- Basic Auth without session management
- Hardcoded credentials:
  - Username: `admin`, Password: `admin123`
  - Username: `user`, Password: `user123`

### CWE-269: Improper Privilege Management
**POST** `/api/admin-only`
- Manual role check with simple if statement
- No Spring Security @PreAuthorize integration
- Query params: `userId`, Body: `{"action": "some_action"}`

### CWE-502: Deserialization of Untrusted Data
**POST** `/api/deserialize-object`
- Deserializes base64-encoded objects without validation
- Uses ObjectInputStream on untrusted data
- Example payload:
```json
{
  "data": "rO0ABXQABXRlc3Q="
}
```

### CWE-200: Exposure of Sensitive Information
- UserService logs passwords in plain text
- Check application logs for exposed credentials
- Triggered on user registration

### CWE-863: Incorrect Authorization
**POST** `/api/edit-user/{id}`
- Flawed authorization check using `==` operator on strings
- Query param: `currentUserId`, Body: `{...updates...}`

### CWE-918: Server-Side Request Forgery (SSRF)
**GET** `/api/fetch-url`
- Fetches content from user-provided URL
- No URL validation or whitelist
- Query param: `url`
- Example: `/api/fetch-url?url=http://localhost:8080/api/users`

### CWE-119: Buffer Copy without Bounds Checking
**POST** `/api/buffer-copy`
- Copies data to fixed-size buffer (5 chars) without size check
- Uses System.arraycopy without validation
- Example payload:
```json
{
  "data": "HelloWorld"
}
```

### CWE-79: Cross-Site Scripting (XSS)
**GET** `/api/xss-profile/{username}`
- Renders user data with th:utext (unescaped)
- No input sanitization
- Example: `/api/xss-profile/<script>alert(1)</script>`

### CWE-89: SQL Injection
**GET** `/api/search-users`
- Uses string concatenation in JPQL query
- Query param: `query`
- Example: `/api/search-users?query=' OR '1'='1`

### CWE-787: Out-of-bounds Write
**POST** `/api/array-write`
- Writes to array without bounds checking
- Payload: `{"index": 20, "value": "X"}`

### CWE-125: Out-of-bounds Read
**POST** `/api/array-read`
- Reads from array without bounds checking
- Payload: `{"index": 20}`

### CWE-22: Path Traversal
**GET** `/api/download-file`
- Downloads files without path validation
- Query param: `filename`
- Example: `/api/download-file?filename=../../etc/passwd`

### CWE-434: Unrestricted File Upload
**POST** `/api/upload-profile`
- Accepts file uploads without extension validation
- Multipart form data

### CWE-416: Use After Free
**POST** `/api/use-resource`
- Clears buffer then accesses it
- Payload: `{"data": "test"}`

### CWE-352: Cross-Site Request Forgery (CSRF)
**POST** `/api/transfer-funds`
- CSRF protection disabled in SecurityConfig
- No CSRF token validation
- Payload: `{"amount": 100.0, "toUser": "victim"}`

### CWE-862: Missing Authorization
**DELETE** `/api/users/{id}`
- No authentication or authorization checks
- Anyone can delete any user

## H2 Database Console

Access the H2 console at: `http://localhost:8080/h2-console`

Connection details:
- JDBC URL: `jdbc:h2:mem:vulnuserdb`
- Username: `sa`
- Password: (empty)

## Testing

Run the integration tests:

```bash
mvn test
```

The test suite includes demonstrations of various vulnerabilities.

## Scanning with SonarQube

### Local SonarQube Setup

1. **Install and Start SonarQube**:
```bash
# Using Docker
docker run -d --name sonarqube -p 9000:9000 sonarqube:latest

# Wait for SonarQube to start (check http://localhost:9000)
# Default credentials: admin/admin
```

2. **Create a Project**:
- Login to SonarQube at `http://localhost:9000`
- Click "Create Project" → "Manually"
- Project key: `vuln-user-manager`
- Display name: `VulnUserManager`
- Generate a token for authentication

3. **Scan the Project**:
```bash
mvn clean verify sonar:sonar \
  -Dsonar.projectKey=vuln-user-manager \
  -Dsonar.projectName=VulnUserManager \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=YOUR_SONARQUBE_TOKEN
```

4. **View Results**:
- Navigate to `http://localhost:9000/dashboard?id=vuln-user-manager`
- Review detected vulnerabilities, code smells, and security hotspots

### Using SonarCloud

```bash
mvn clean verify sonar:sonar \
  -Dsonar.projectKey=YOUR_PROJECT_KEY \
  -Dsonar.organization=YOUR_ORG \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.login=YOUR_SONARCLOUD_TOKEN
```

### Expected SonarQube Findings

SonarQube should detect the following security issues:

| CWE | Severity | Description |
|-----|----------|-------------|
| CWE-94 | Critical | Code Injection via ScriptEngine |
| CWE-502 | Critical | Deserialization of untrusted data |
| CWE-77, CWE-78 | Critical | OS Command Injection |
| CWE-89 | Critical | SQL Injection via string concatenation |
| CWE-79 | High | Cross-Site Scripting (XSS) |
| CWE-918 | High | Server-Side Request Forgery (SSRF) |
| CWE-22 | High | Path Traversal |
| CWE-287 | High | Plain-text password storage |
| CWE-352 | High | CSRF protection disabled |
| CWE-862 | High | Missing authorization checks |
| CWE-20 | Medium | Improper input validation |
| CWE-200 | Medium | Sensitive data in logs |
| CWE-269 | Medium | Improper privilege management |
| CWE-863 | Medium | Incorrect authorization logic |
| CWE-787, CWE-125, CWE-119 | Medium | Buffer overflow issues |

## Project Structure

```
src/
├── main/
│   ├── java/com/enterprise/vulnusermanager/
│   │   ├── VulnUserManagerApplication.java
│   │   ├── config/
│   │   │   └── SecurityConfig.java
│   │   ├── controller/
│   │   │   ├── AdminController.java          (CWE-269)
│   │   │   ├── ArrayController.java          (CWE-787, CWE-125, CWE-119)
│   │   │   ├── CodeController.java           (CWE-94)
│   │   │   ├── FileController.java           (CWE-22, CWE-434)
│   │   │   ├── FinanceController.java        (CWE-352)
│   │   │   ├── ResourceController.java       (CWE-416)
│   │   │   ├── SerializeController.java      (CWE-502)
│   │   │   ├── SystemController.java         (CWE-77, CWE-78)
│   │   │   ├── UserController.java           (CWE-20, CWE-79, CWE-89, CWE-862, CWE-863)
│   │   │   └── WebController.java            (CWE-918)
│   │   ├── entity/
│   │   │   └── User.java
│   │   ├── repository/
│   │   │   └── UserRepository.java
│   │   └── service/
│   │       ├── ArrayService.java
│   │       └── UserService.java              (CWE-20, CWE-200)
│   └── resources/
│       ├── application.yml
│       ├── static/
│       │   └── index.html
│       └── templates/
│           └── profile.html                  (CWE-79)
└── test/
    └── java/com/enterprise/vulnusermanager/
        └── VulnerableAppTest.java
```

## Security Best Practices (What NOT to do)

This application violates numerous security best practices:

1. ❌ **Never** execute user-provided code
2. ❌ **Never** store passwords in plain text
3. ❌ **Never** use string concatenation in SQL/JPQL queries
4. ❌ **Never** disable CSRF protection
5. ❌ **Never** execute system commands with user input
6. ❌ **Never** deserialize untrusted data
7. ❌ **Never** render user input without escaping
8. ❌ **Never** access files without path validation
9. ❌ **Never** log sensitive information (passwords, tokens, etc.)
10. ❌ **Never** perform manual authorization checks without security framework integration

## Educational Purpose

This application is designed to help:
- Security engineers test SAST tools
- Developers learn about common vulnerabilities
- Teams practice secure code review
- Organizations validate their security scanning pipeline

## Disclaimer

⚠️ **DO NOT USE IN PRODUCTION**

This application is intentionally vulnerable and should only be used in:
- Isolated development environments
- Security training labs
- SAST tool evaluation environments
- Offline/air-gapped testing environments

## License

This project is provided for educational purposes only.

## Contributing

If you find additional vulnerabilities to demonstrate or improvements to the existing examples, please contribute!

## References

- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SonarQube Security Rules](https://rules.sonarsource.com/)
