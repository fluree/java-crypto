package com.fluree.crypto;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * A class to represent a keypair, with a private key and a public key.
 */
public class Keypair {
    private final String privateKey;
    private final String publicKey;

    /**
     * Constructor for a keypair, with a private key and a public key. The private
     * and public keys can be retrieved using the getPrivateKey and getPublicKey
     * methods.
     * 
     * @param privateKey The private key of the keypair in hex format.
     * @param publicKey  The public key of the keypair in hex format.
     */
    Keypair(BigInteger privateKey, ECPoint publicKey) {
        String tempPrivateKey = privateKey.toString(16);
        if (tempPrivateKey.length() % 2 != 0) {
            tempPrivateKey = "0" + tempPrivateKey;
        }
        this.privateKey = tempPrivateKey;

        String unpaddedX = publicKey.getAffineXCoord().toBigInteger().toString(16);
        String x = Utils.padToLength(unpaddedX, 64);
        String y = publicKey.getAffineYCoord().toBigInteger().toString(16);
        String publicKeyFinal = Signature.x962Encode(x, y, true);

        this.publicKey = publicKeyFinal;
    }

    /**
     * Getter for the private key in hex format.
     */
    public String getPrivateKey() {
        return this.privateKey;
    }

    /**
     * Getter for the public key in hex format.
     */
    public String getPublicKey() {
        return this.publicKey;
    }

}
