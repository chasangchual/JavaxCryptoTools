package com.bloomingbread.blockchain.myblockchain;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class BlockHeader {
    private final int version = HashUtils.getHeaderVersion() ;
    private final String previousBlockHash;
    private int merkleRootHash;
    private int difficultyTarget;
    private int nonce;

    public BlockHeader(final String previousBlockHash, final int difficultyTarget, final int nonce) {
        this.previousBlockHash = previousBlockHash;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
    }

    public int getVersion() {
        return version;
    }

    public int getDifficultyTarget() {
        return difficultyTarget;
    }

    public String getPreviousBlockHash() {
        return previousBlockHash;
    }

    public int increaseAndGetNonce() {
        return ++nonce;
    }

    public int getNonce() {
        return nonce;
    }
}
