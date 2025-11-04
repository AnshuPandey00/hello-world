package com.enterprise.vulnusermanager.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.util.HashMap;
import java.util.Map;

/**
 * CodeController
 * VULNERABLE: CWE-94 Code Injection
 * Demonstrates code injection vulnerability through unsafe script execution
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@RestController
@RequestMapping("/api")
@Slf4j
public class CodeController {

    /**
     * VULNERABLE: Code Injection Endpoint (CWE-94)
     * Executes arbitrary JavaScript code using Nashorn script engine
     * NO input validation, NO sandboxing - INTENTIONALLY VULNERABLE
     * @param request JSON containing script string
     * @return script execution result as JSON
     */
    @PostMapping("/eval-code")
    public ResponseEntity<Map<String, Object>> evalCode(@RequestBody Map<String, String> request) {
        String script = request.get("script");

        log.info("POST /api/eval-code - VULNERABLE Code Injection endpoint");
        log.warn("SECURITY WARNING: Executing arbitrary code - CWE-94 Code Injection vulnerability!");
        log.warn("VULNERABLE: Script content: {}", script);

        Map<String, Object> result = new HashMap<>();

        try {
            // VULNERABLE: Executing arbitrary user-provided code without validation
            // Uses Nashorn JavaScript engine to execute untrusted code
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("nashorn");

            log.warn("VULNERABLE: Executing untrusted script without sandboxing!");

            // Execute the user-provided script
            Object scriptResult = engine.eval(script);

            result.put("success", true);
            result.put("result", scriptResult != null ? scriptResult.toString() : "null");
            result.put("script", script);
            result.put("warning", "Code executed without validation - CWE-94");

            log.warn("Script executed WITHOUT input validation or sandboxing!");

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("Error executing script: {}", e.getMessage());
            result.put("success", false);
            result.put("error", "Error executing script: " + e.getMessage());
            result.put("script", script);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

}
