package com.enterprise.vulnusermanager;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * VulnerableAppTest
 * Integration tests for the intentionally vulnerable application
 * Tests demonstrate vulnerabilities without asserting success
 * These tests verify that vulnerable endpoints are accessible
 */
@SpringBootTest
@AutoConfigureMockMvc
public class VulnerableAppTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * Test CWE-79 XSS vulnerability endpoint
     * This test demonstrates that XSS payloads are accepted
     * without sanitization or encoding
     * NOTE: We're NOT asserting success - just checking endpoint accessibility
     */
    @Test
    public void testXssProfileEndpoint_AcceptsScriptPayload() throws Exception {
        // XSS payload - script tag that would execute in browser
        String xssPayload = "<script>alert(1)</script>";
        String encodedPayload = URLEncoder.encode(xssPayload, StandardCharsets.UTF_8);

        // Send request to vulnerable XSS endpoint
        // The endpoint will render this unsafely in the template
        mockMvc.perform(get("/api/xss-profile/" + encodedPayload))
                .andExpect(status().isOk()); // Endpoint is accessible

        // NOTE: Not asserting that XSS is prevented - this is intentionally vulnerable
        // A SAST tool should detect the use of th:utext in profile.html template
    }

    /**
     * Test CWE-89 SQL Injection vulnerability endpoint
     * This test demonstrates that SQL injection payloads are accepted
     * without parameterization or sanitization
     */
    @Test
    public void testSqlInjectionEndpoint_AcceptsMaliciousQuery() throws Exception {
        // SQL injection payload
        String sqlInjectionPayload = "' OR '1'='1";

        // Send request to vulnerable SQL injection endpoint
        mockMvc.perform(get("/api/search-users")
                        .param("query", sqlInjectionPayload))
                .andExpect(status().isOk()); // Endpoint is accessible

        // NOTE: Not asserting SQL injection is prevented - intentionally vulnerable
        // SAST tool should detect string concatenation in JPQL query
    }

    /**
     * Test CWE-78 OS Command Injection vulnerability endpoint
     * This test demonstrates the command injection endpoint is accessible
     */
    @Test
    public void testCommandInjectionEndpoint_IsAccessible() throws Exception {
        // Test that the vulnerable command injection endpoint exists
        mockMvc.perform(get("/api/system-ping")
                        .param("host", "localhost"))
                .andExpect(status().isMethodNotAllowed()); // POST expected, not GET

        // NOTE: Actual command injection test would require POST
        // SAST tool should detect Runtime.exec() with string concatenation
    }

    /**
     * Test CWE-22 Path Traversal vulnerability endpoint
     * This test demonstrates that path traversal payloads are accepted
     */
    @Test
    public void testPathTraversalEndpoint_AcceptsTraversalPayload() throws Exception {
        // Path traversal payload
        String pathTraversalPayload = "../../etc/passwd";

        // Send request to vulnerable file download endpoint
        // Expects 500 because file doesn't exist, but the vulnerability is that
        // the path traversal payload is accepted without validation
        mockMvc.perform(get("/api/download-file")
                        .param("path", pathTraversalPayload))
                .andExpect(status().isInternalServerError()); // File doesn't exist but path traversal accepted

        // NOTE: Not asserting path traversal is prevented - intentionally vulnerable
        // SAST tool should detect unsanitized file path usage
    }

    /**
     * Test that all users endpoint is publicly accessible
     * Demonstrates CWE-862 Missing Authorization
     */
    @Test
    public void testGetAllUsers_NoAuthenticationRequired() throws Exception {
        // Should be protected but is publicly accessible
        mockMvc.perform(get("/api/users"))
                .andExpect(status().isOk()); // No authentication required

        // NOTE: SAST tool should detect missing @PreAuthorize annotations
    }

}
