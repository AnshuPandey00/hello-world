package com.enterprise.vulnusermanager.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

/**
 * SystemController
 * VULNERABLE: CWE-78 OS Command Injection
 * Demonstrates OS command injection vulnerability through unsafe command execution
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@RestController
@RequestMapping("/api")
@Slf4j
public class SystemController {

    /**
     * VULNERABLE: OS Command Injection Endpoint (CWE-78)
     * Executes system ping command with user-controlled input
     * Uses Runtime.getRuntime().exec() with string concatenation
     * NO input validation, NO shell escaping - INTENTIONALLY VULNERABLE
     * @param host the hostname or IP address to ping (user-controlled)
     * @return command output as JSON
     */
    @PostMapping("/system-ping")
    public ResponseEntity<Map<String, Object>> systemPing(@RequestParam String host) {
        log.info("POST /api/system-ping?host={} - VULNERABLE OS Command Injection endpoint", host);
        log.warn("SECURITY WARNING: Command injection via string concatenation - CWE-78 OS Command Injection vulnerability!");

        Map<String, Object> result = new HashMap<>();

        try {
            // VULNERABLE: Direct string concatenation without escaping or validation
            // Allows command injection like: "google.com; cat /etc/passwd"
            // or "google.com && whoami" or "google.com | ls -la"
            String command = "ping " + host;

            log.warn("VULNERABLE: Executing command without validation: {}", command);
            log.warn("VULNERABLE: No shell escaping - allows command injection!");

            // VULNERABLE: Runtime.exec() with concatenated user input
            Process process = Runtime.getRuntime().exec(command);

            // Capture command output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

            StringBuilder output = new StringBuilder();
            StringBuilder errorOutput = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            while ((line = errorReader.readLine()) != null) {
                errorOutput.append(line).append("\n");
            }

            int exitCode = process.waitFor();

            result.put("command", command);
            result.put("output", output.toString());
            result.put("error", errorOutput.toString());
            result.put("exitCode", exitCode);
            result.put("warning", "Command executed without input validation - CWE-78");

            log.warn("Command executed WITHOUT input validation or sanitization!");

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("Error executing command: {}", e.getMessage());
            result.put("error", "Error executing command: " + e.getMessage());
            result.put("host", host);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

}
