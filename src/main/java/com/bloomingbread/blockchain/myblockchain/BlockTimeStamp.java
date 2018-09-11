package com.bloomingbread.blockchain.myblockchain;

import java.time.Instant;

public class BlockTimeStamp {
    final long epoch;
    final int nano;
    public BlockTimeStamp() {
        epoch = Instant.now().toEpochMilli();
        nano = Instant.now().getNano();
    }

    public long getEpoch() {
        return epoch;
    }
    public int getNano() {
        return nano;
    }

    @Override
    public String toString() {
        return String.valueOf(epoch);
    }
}
