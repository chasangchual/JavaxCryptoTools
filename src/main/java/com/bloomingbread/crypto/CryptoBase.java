package com.bloomingbread.crypto;

import com.bloomingbread.crypto.JCEProviderInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public abstract class CryptoBase {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static SecureRandom secureRandom = new SecureRandom();

    final String providerName ;
    final String serviceName ;
    JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();

    public CryptoBase(final String providerName, final String serviceName) {
        if(jceProviderInfo.isAvailableProvider(providerName)) {
            this.providerName = providerName;
        } else {
            throw new RuntimeException(String.format("specified provider, %s is not available.", providerName));
        }

        if(jceProviderInfo.isAvailableService(providerName, serviceName)) {
            this.serviceName = serviceName;
        } else {
            throw new RuntimeException(String.format("specified crypto service, %s is not available in %s.",
                    serviceName, providerName));
        }
    }

    public String getProviderName() {
        return providerName;
    }
    public String getServiceName() {
        return serviceName;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("provider: " + providerName + "\n");
        sb.append("crypto service: " + serviceName + "\n");
        sb.append(Arrays.toString(JCEProviderInfo.instance().getAvailableAlgorithm(providerName, serviceName).toArray()));
        return sb.toString();
    }
}
