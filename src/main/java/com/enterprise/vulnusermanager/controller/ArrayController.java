package com.enterprise.vulnusermanager.controller;

import com.enterprise.vulnusermanager.service.ArrayService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * ArrayController
 * VULNERABLE: CWE-787 Out-of-bounds Write
 * Demonstrates buffer overflow vulnerability through unchecked array writes
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
}
