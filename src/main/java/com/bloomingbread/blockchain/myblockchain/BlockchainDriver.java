package com.bloomingbread.blockchain.myblockchain;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class BlockchainDriver {

    List<Block> blockchain = new ArrayList<Block>();
    public static int difficultyTarget = 2 ;
    public static List<Block> blockChain = new ArrayList<>();

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        // Genesis block
        Block genesisBlock = new Block("", "Hosang sent 1k Bitcoins to Zuckerberg.", difficultyTarget);
        genesisBlock.mind();
        System.out.println("Block Hash : " + genesisBlock.getHash() + ", nonce : " + Integer.toString(genesisBlock.getBlockHeader().getNonce()));
        blockChain.add(genesisBlock);

        try {
            for(int i = 1; i < 10; i++) {
                Block block = new Block(blockChain.get(i - 1).getHash(), String.format("[%d] block chain transaction", i), difficultyTarget);
                block.mind();
                System.out.println("Block Hash : " + block.getHash() + ", nonce : " + Integer.toString(block.getBlockHeader().getNonce()));
                blockChain.add(block);
            }

            validateBlockchain();
            System.out.println("block chain validation completed.");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    private static void validateBlockchain() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        for(int i = 1 ; i < blockChain.size(); i++) {
            Block prevBlock = blockChain.get(i - 1);
            Block currBlock = blockChain.get(i);
            if(! currBlock.getHash().equals(currBlock.generateHash())) {
                System.out.println(String.format("chain # %d - failed to validate the generated hash"));
                throw new RuntimeException("chain # %d - failed to validate the generated hash");
            }

            if(! currBlock.getBlockHeader().getPreviousBlockHash().equals(prevBlock.getHash())) {
                System.out.println(String.format("chain # %d - failed to validate the previous hash"));
                throw new RuntimeException("chain # %d - failed to validate the previous hash");
            }
        }
    }

}