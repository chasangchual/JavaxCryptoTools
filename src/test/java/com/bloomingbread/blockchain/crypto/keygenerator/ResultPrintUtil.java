package com.bloomingbread.blockchain.crypto.keygenerator;

import java.util.List;
import java.util.Map;

public class ResultPrintUtil {
    public static void print(Map<String, Map<String, List<String>>> result) {
        result.entrySet().forEach(providerEntry -> {
            System.out.println(String.format("- %s", providerEntry.getKey()));
            providerEntry.getValue().entrySet().forEach(cipherAlgorithmEntry -> {
                cipherAlgorithmEntry.getValue().forEach(keyAlgorithm -> {
                    System.out.println(String.format("Cipher - %s, Key - %s", cipherAlgorithmEntry.getKey(), keyAlgorithm));
                });
            });
        });
    }
}
