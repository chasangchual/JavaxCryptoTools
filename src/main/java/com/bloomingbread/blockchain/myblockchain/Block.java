package com.bloomingbread.blockchain.myblockchain;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class Block {
    private int blockSize;            // Ignore for now.
    private BlockHeader blockHeader;
    private int transactionCount;     // Ignore for now.
    private String data;
    private BlockTimeStamp timeStamp;
    private String blockHash;

    public Block(final String previousHash, final String data, final int difficultyTarget) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        timeStamp = new BlockTimeStamp();

        String seed = previousHash + data + timeStamp.toString();
        this.blockHeader = new BlockHeader(previousHash, difficultyTarget, 0);
        this.data = data;
        this.timeStamp = new BlockTimeStamp();
    }

    public String getHash() {
        return blockHash;
    }

    public BlockHeader getBlockHeader() {
        return new BlockHeader(blockHeader.getPreviousBlockHash(), blockHeader.getDifficultyTarget(), blockHeader.getNonce());
    }

    public String generateHash() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return HashUtils.getSha256HashString(blockHeader.getPreviousBlockHash()
                + data + timeStamp.toString() + String.valueOf(blockHeader.getNonce()));
    }

    private String generateNewHash() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return HashUtils.getSha256HashString(blockHeader.getPreviousBlockHash()
                + data + timeStamp.toString() + String.valueOf(blockHeader.increaseAndGetNonce()));
    }

    public void mind() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        String target = new String(new char[blockHeader.getDifficultyTarget()]).replace("\0", "0");
        try {
            String minedHash = generateNewHash();
            while(!minedHash.substring(0, blockHeader.getDifficultyTarget()).equals(target)) {
                minedHash = generateNewHash() ;
            }
            blockHash = minedHash;
        } catch (UnsupportedEncodingException e) {

        } catch (NoSuchAlgorithmException e) {
        }
    }
}