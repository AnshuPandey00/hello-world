package com.enterprise.vulnusermanager.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * WebController
 * VULNERABLE: CWE-918 Server-Side Request Forgery (SSRF)
 * Demonstrates SSRF vulnerability through unvalidated URL fetching
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@RestController
@RequestMapping("/api")
@Slf4j
public class WebController {

    /**
     * VULNERABLE: Server-Side Request Forgery (CWE-918)
     * Fetches content from user-provided URL without validation
     * Uses RestTemplate.getForObject() with untrusted URL
     * NO URL whitelist, NO validation - INTENTIONALLY VULNERABLE
     * @param url the URL to fetch (user-controlled)
     * @return fetched content as JSON
     */
    @GetMapping("/fetch-url")
    public ResponseEntity<Map<String, Object>> fetchUrl(@RequestParam String url) {
        log.info("GET /api/fetch-url?url={} - VULNERABLE SSRF endpoint", url);
        log.warn("SECURITY WARNING: Fetching untrusted URL - CWE-918 Server-Side Request Forgery vulnerability!");

        Map<String, Object> result = new HashMap<>();

        try {
            // VULNERABLE: RestTemplate with user-provided URL
            // No validation, no whitelist, no URL parsing
            // Allows access to internal services, localhost, cloud metadata, etc.
            log.warn("VULNERABLE: Fetching URL without validation: {}", url);
            log.warn("VULNERABLE: Can access internal services, localhost, cloud metadata!");

            RestTemplate restTemplate = new RestTemplate();

            // VULNERABLE: Direct fetch without URL validation
            String response = restTemplate.getForObject(url, String.class);

            result.put("success", true);
            result.put("url", url);
            result.put("response", response);
            result.put("warning", "URL fetched without validation - CWE-918");

            log.warn("URL fetched WITHOUT validation or whitelist!");

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("Error fetching URL: {}", e.getMessage());
            result.put("success", false);
            result.put("url", url);
            result.put("error", "Error fetching URL: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

}
