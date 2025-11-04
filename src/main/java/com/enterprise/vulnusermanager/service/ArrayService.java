package com.enterprise.vulnusermanager.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * ArrayService
 * VULNERABLE: CWE-787 Out-of-bounds Write
 * Performs unchecked writes to a fixed-size buffer
 * INTENTIONALLY VULNERABLE for SAST detection
 */
@Service
@Slf4j
public class ArrayService {

    /**
     * VULNERABLE: Out-of-bounds Write (CWE-787)
     * Writes to a fixed-size array without bounds checking
     * NO INPUT VALIDATION - accepts any index value
     * NO TRY-CATCH - allows exceptions to propagate
     * @param index the array index to write to (UNCHECKED!)
     * @param value the string value to extract first character from
     * @return Map containing the buffer state and operation details
     */
    public Map<String, Object> writeToBuffer(Integer index, String value) {
        char[] buffer = new char[10];

        log.info("Writing to buffer at index: {}", index);
        log.warn("SECURITY WARNING: NO BOUNDS CHECKING - index can be out of range!");

        // VULNERABLE: No bounds checking before array access
        // This can cause ArrayIndexOutOfBoundsException or memory corruption
        buffer[index] = value.charAt(0);

        log.info("Successfully wrote '{}' to buffer[{}]", value.charAt(0), index);

        Map<String, Object> result = new HashMap<>();
        result.put("buffer", buffer);
        result.put("index", index);
        result.put("writtenValue", value.charAt(0));
        result.put("bufferSize", buffer.length);

        return result;
    }
}
