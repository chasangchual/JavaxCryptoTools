package com.bloomingbread.blockchain.crypto.keygenerator;

import com.bloomingbread.crypto.JCEProviderInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.Arrays;

public abstract class CryptoBase {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    final String providerName ;
    final String serviceName ;
    String recentAlgorithm = "" ;
    JCEProviderInfo jceProviderInfo = JCEProviderInfo.instance();

    public CryptoBase(final String providerName, final String serviceName, final String defaultAlgorithm) {
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

        if(jceProviderInfo.isAvailableAlgorithm(providerName, serviceName, defaultAlgorithm)) {
            this.recentAlgorithm = defaultAlgorithm;
        } else {
            throw new RuntimeException(String.format("specified algorithm, %s is not available in %s, in %s.",
                    defaultAlgorithm, serviceName, providerName));
        }
    }

    public String getProviderName() {
        return providerName;
    }

    public String getServiceName() {
        return serviceName;
    }

    public String getRecentlyUsedAlgorithm() {
        return recentAlgorithm;
    }

    public void updateRecentlyUsedAlgorithm(final String algorithm) {
        if(jceProviderInfo.isAvailableAlgorithm(providerName, serviceName, algorithm)) {
            this.recentAlgorithm = algorithm;
        } else {
            throw new RuntimeException(String.format("specified crypto service, %s is not available in %s.",
                    serviceName, providerName));
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("provider: " + providerName + "\n");
        sb.append("crypto service: " + serviceName + "\n");
        sb.append("recently used algorithm" + recentAlgorithm + "\n");
        sb.append(Arrays.toString(JCEProviderInfo.instance().getAvailableAlgorithm(providerName, serviceName).toArray()));
        return sb.toString();
    }
}
