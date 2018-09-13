package com.bloomingbread.blockchain.crypto.keygenerator;

import java.util.List;
import java.util.Map;

public class ResultPrintUtil {
    public static void print(Map<String, Map<String, List<String>>> result) {
        result.entrySet().forEach(providerEntry -> {
            providerEntry.getValue().entrySet().forEach(cipherAlgorithmEntry -> {
                cipherAlgorithmEntry.getValue().forEach(keyAlgorithm -> {
                    System.out.println(String.format("%s, %s, %s", providerEntry.getKey(), cipherAlgorithmEntry.getKey(), keyAlgorithm));
                });
            });
        });
    }
}
