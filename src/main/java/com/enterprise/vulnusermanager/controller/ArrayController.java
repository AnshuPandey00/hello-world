package com.enterprise.vulnusermanager.controller;

import com.enterprise.vulnusermanager.service.ArrayService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
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

    /**
     * VULNERABLE: Buffer Copy without Size Check (CWE-119)
     * Copies user data to fixed-size buffer without checking size
     * Uses System.arraycopy without bounds validation
     * INTENTIONALLY VULNERABLE for SAST detection
     * @param request JSON containing data string
     * @return copy result as JSON
     */
    @PostMapping("/buffer-copy")
    public ResponseEntity<Map<String, Object>> bufferCopy(@RequestBody Map<String, String> request) {
        String data = request.get("data");

        log.info("POST /api/buffer-copy - VULNERABLE Buffer Copy endpoint");
        log.warn("SECURITY WARNING: Buffer copy without size check - CWE-119 Buffer Copy vulnerability!");

        Map<String, Object> result = new HashMap<>();

        try {
            // VULNERABLE: Creating fixed-size destination buffer
            char[] src = data.toCharArray();
            char[] dest = new char[5]; // Fixed size of 5 characters

            log.warn("VULNERABLE: Source length: {}, Destination size: 5", src.length);
            log.warn("VULNERABLE: No size check before copying!");

            // VULNERABLE: System.arraycopy without bounds checking
            // If src.length > 5, this will throw ArrayIndexOutOfBoundsException
            // This demonstrates unsafe buffer copy operations
            System.arraycopy(src, 0, dest, 0, src.length);

            result.put("success", true);
            result.put("sourceLength", src.length);
            result.put("destSize", dest.length);
            result.put("copied", new String(dest));
            result.put("warning", "Buffer copy without size validation - CWE-119");

            log.warn("Buffer copy executed WITHOUT size validation!");

            return ResponseEntity.ok(result);

        } catch (ArrayIndexOutOfBoundsException e) {
            log.error("ArrayIndexOutOfBoundsException: {}", e.getMessage());
            result.put("success", false);
            result.put("error", "Buffer overflow: " + e.getMessage());
            result.put("sourceLength", data.length());
            result.put("destSize", 5);
            result.put("vulnerability", "CWE-119: Buffer copy without size check");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        } catch (Exception e) {
            log.error("Error during buffer copy: {}", e.getMessage());
            result.put("success", false);
            result.put("error", "Error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }
}
