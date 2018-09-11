package com.bloomingbread.blockchain.crypto.keygenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.jca.Providers;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AlgorithmDictionary {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {

        List<Provider> providers = Providers.getProviderList().providers();
        for(Provider provider : providers) {
            System.out.println("-----------------------------------------------------");
            System.out.println(provider.getName());
            System.out.println(provider.getInfo());
            System.out.println(provider.toString());
            System.out.println("-----------------------------------------------------");
            Set<Provider.Service> services = provider.getServices();
            Map<String,List<String>> serviceDetail = new HashMap<>();

            for(Provider.Service service : services) {
                if(!serviceDetail.containsKey(service.getType())) {
                    serviceDetail.put(service.getType(), new ArrayList<String>());
                }
                List<String> info = serviceDetail.get(service.getType());
                info.add(String.format("Algorithm:%s \n %s",service.getAlgorithm(), service.toString()));
            }

            for(Map.Entry<String, List<String>> entry : serviceDetail.entrySet()) {
                System.out.println("{{" + entry.getKey() + "}}");
            }
            System.out.println();
            for(Map.Entry<String, List<String>> entry : serviceDetail.entrySet()) {
                System.out.println("{{" + entry.getKey() + "}}");
                for(String info : entry.getValue()) {
                    System.out.println(info);
                }
            }

            System.out.println("==================================================================");
        }
    }

}
