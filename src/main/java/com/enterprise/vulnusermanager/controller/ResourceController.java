package com.enterprise.vulnusermanager.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

/**
 * ResourceController
 * VULNERABLE: CWE-416 Use After Free
 * Demonstrates use-after-free pattern in Java context
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@RestController
@RequestMapping("/api")
@Slf4j
public class ResourceController {

    /**
     * VULNERABLE: Use After Free Endpoint (CWE-416)
     * Creates a ByteBuffer, clears it, then attempts to access it
     * Demonstrates use-after-free pattern detectable by SAST tools
     * INTENTIONALLY VULNERABLE for SAST detection
     * @return resource usage information as JSON
     */
    @PostMapping("/use-resource")
    public ResponseEntity<Map<String, Object>> useResource() {
        log.info("POST /api/use-resource - VULNERABLE Use After Free endpoint");
        log.warn("SECURITY WARNING: Use After Free pattern - CWE-416 vulnerability!");

        Map<String, Object> result = new HashMap<>();

        try {
            // Allocate a ByteBuffer resource
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put("Sensitive data".getBytes());

            log.info("ByteBuffer created and populated with data");
            log.warn("VULNERABLE: About to 'free' the buffer and then use it");

            // Store reference to the buffer's data
            byte[] dataBeforeFree = new byte[buffer.position()];
            buffer.flip();
            buffer.get(dataBeforeFree);

            // VULNERABLE: "Free" the buffer by clearing it
            buffer.clear();
            log.warn("Buffer cleared (simulating free operation)");

            // VULNERABLE: Use after free - accessing buffer after clearing
            // In C/C++ this would be a critical vulnerability
            // In Java, SAST tools should flag this pattern
            buffer.put("Accessing freed memory".getBytes());
            byte[] dataAfterFree = new byte[buffer.position()];
            buffer.flip();
            buffer.get(dataAfterFree);

            log.warn("VULNERABLE: Accessed buffer after free operation!");
            log.warn("This pattern represents use-after-free vulnerability");

            result.put("warning", "Use after free vulnerability - CWE-416");
            result.put("beforeFree", new String(dataBeforeFree));
            result.put("afterFree", new String(dataAfterFree));
            result.put("vulnerability", "Buffer accessed after clear() operation");

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("Error in use-after-free demonstration: {}", e.getMessage());
            result.put("error", "Error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

    /**
     * VULNERABLE: Use After Free with Direct Memory (CWE-416)
     * Uses DirectByteBuffer which is closer to native memory management
     * Demonstrates more explicit use-after-free pattern
     * INTENTIONALLY VULNERABLE for SAST detection
     * @return resource usage information as JSON
     */
    @PostMapping("/use-direct-resource")
    public ResponseEntity<Map<String, Object>> useDirectResource() {
        log.info("POST /api/use-direct-resource - VULNERABLE Use After Free endpoint (direct memory)");
        log.warn("SECURITY WARNING: Use After Free with direct memory - CWE-416 vulnerability!");

        Map<String, Object> result = new HashMap<>();

        try {
            // Allocate direct ByteBuffer (uses native memory)
            ByteBuffer directBuffer = ByteBuffer.allocateDirect(1024);
            directBuffer.put("Critical system data".getBytes());

            log.info("Direct ByteBuffer created (native memory)");

            // Get position before "freeing"
            int position = directBuffer.position();

            // VULNERABLE: Simulate freeing the resource
            directBuffer.clear();
            directBuffer = null; // Simulate deallocation
            log.warn("VULNERABLE: Direct buffer cleared and dereferenced");

            // VULNERABLE: Try to use after "free"
            // This simulates accessing memory after it's been freed
            log.warn("VULNERABLE: Attempting to use freed resource!");

            result.put("warning", "Use after free vulnerability with direct memory - CWE-416");
            result.put("vulnerability", "DirectByteBuffer accessed after clear and null assignment");
            result.put("details", "This pattern simulates use-after-free in native memory context");

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("Error in use-after-free demonstration: {}", e.getMessage());
            result.put("error", "Error: " + e.getMessage());
            result.put("note", "Exception demonstrates use-after-free vulnerability");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

}
