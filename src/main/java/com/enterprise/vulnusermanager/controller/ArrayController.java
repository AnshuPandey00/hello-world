package com.enterprise.vulnusermanager.controller;

import com.enterprise.vulnusermanager.service.ArrayService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * ArrayController
 * VULNERABLE: CWE-787 Out-of-bounds Write & CWE-125 Out-of-bounds Read
 * Demonstrates buffer overflow and out-of-bounds read vulnerabilities
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class ArrayController {

    private final ArrayService arrayService;

    /**
     * VULNERABLE: Out-of-bounds Write Endpoint (CWE-787)
     * Accepts index and value without bounds checking
     * Writes to a fixed-size array without validation
     * INTENTIONALLY VULNERABLE for SAST detection
     * @param request JSON containing index and value
     * @return the modified array as JSON
     */
    @PostMapping("/array-write")
    public ResponseEntity<Map<String, Object>> writeToArray(@RequestBody Map<String, Object> request) {
        Integer index = (Integer) request.get("index");
        String value = (String) request.get("value");

        log.info("POST /api/array-write - Writing to array at index: {} with value: {}", index, value);
        log.warn("SECURITY WARNING: No bounds checking - CWE-787 Out-of-bounds Write vulnerability!");

        Map<String, Object> result = arrayService.writeToBuffer(index, value);

        return ResponseEntity.ok(result);
    }

    /**
     * VULNERABLE: Out-of-bounds Read Endpoint (CWE-125)
     * Accepts index without bounds checking
     * Reads from a fixed-size buffer (size 10) without validation
     * INTENTIONALLY VULNERABLE for SAST detection
     * @param request JSON containing index
     * @return the read character and buffer info as JSON
     */
    @PostMapping("/array-read")
    public ResponseEntity<Map<String, Object>> readFromArray(@RequestBody Map<String, Object> request) {
        Integer index = (Integer) request.get("index");

        log.info("POST /api/array-read - Reading from array at index: {}", index);
        log.warn("SECURITY WARNING: No bounds checking - CWE-125 Out-of-bounds Read vulnerability!");

        Map<String, Object> result = arrayService.readFromBuffer(index);

        return ResponseEntity.ok(result);
    }
}
