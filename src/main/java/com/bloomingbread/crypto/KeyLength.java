package com.bloomingbread.crypto;

import java.util.HashMap;
import java.util.Map;

public class KeyLength {
    private static Map<String, Integer> keyLengths = new HashMap<>();
    static {
        keyLengths.put("", 0);
    }

    public static int getMaxKeyLength(final String algorithm) {
        return 0;
    }
}
