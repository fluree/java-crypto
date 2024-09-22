package com.fluree.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.security.*;
import java.util.*;

import org.bitcoinj.core.Base58;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * A utility class for cryptographic operations with Fluree, like generating
 * keypairs and signing and verifying JWS.
 * <p>
 * This class provides methods to generate keypairs, derive public keys and
 * account ids, create JWS, and verify JWS.
 * </p>
 */
public class Crypto {

    private static final String joseHeader = "{\"alg\":\"ES256K-R\",\"b64\":false,\"crit\":[\"b64\"]}";

    private static ECDomainParameters secp256k1;

    static {
        X9ECParameters params = ECNamedCurveTable.getByName("secp256k1");
        secp256k1 = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // -----------------------
    // Public API methods
    // -----------------------

    /**
     * Creates a JWS using the provided payload and private key. Sent this JWS to
     * /create, /query, or /transact endpoints with the application/jwt content type
     * header
     * 
     * @param payload       The stringified payload to sign.
     * @param privateKeyHex The hex string of the private key to sign the payload
     *                      with.
     * @return The JWS string.
     * @throws Exception If an error occurs during JWS creation.
     */
    public static String createJws(String payload, String privateKeyHex) throws Exception {
        String encodedHeader = base64UrlEncode(joseHeader);

        String encodedPayload = base64UrlEncode(payload);

        String signingInput = encodedHeader + "." + encodedPayload;

        String signature = signWithSecp256k1(signingInput, privateKeyHex);

        return encodedHeader + "." + encodedPayload + "." + base64UrlEncode(signature);
    }

    /**
     * Verifies a JWS and returns a HashMap with a payload and pubkey.
     * 
     * @param jwsString The JWS string to verify.
     * @return A map containing the keys "payload" and "pubkey".
     * @throws Exception If an error occurs during JWS verification.
     */
    public static HashMap<String, String> verifyJws(String jwsString) throws Exception {
        String[] parts = jwsString.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWS format.");
        }

        String b64header = parts[0];
        String b64payload = parts[1];
        String b64signature = parts[2];

        String header = base64ToString(b64header);
        String payload = base64ToString(b64payload);
        String signature = base64ToString(b64signature);

        String signingInput = b64header + "." + b64payload;
        String pubkey = recoverPublicKey(signingInput, signature);
        if (!joseHeader.equals(header)) {
            throw new IllegalArgumentException("Unsupported JWS header.");
        }
        boolean verification = Signature.verify(pubkey, signingInput, signature);
        if (!verification) {
            throw new IllegalArgumentException("JWS verification failed.");
        }
        return new HashMap<String, String>() {
            {
                put("payload", payload);
                put("pubkey", pubkey);
            }
        };
    }

    /**
     * Generates a keypair. See {@link Keypair} for more information.
     * 
     * @return A Keypair object containing the private and public keys.
     * @throws Exception If an error occurs during keypair generation.
     */
    public static Keypair generateKeyPair() throws Exception {
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        SecureRandom rng = new SecureRandom();
        ECKeyGenerationParameters params = new ECKeyGenerationParameters(secp256k1, rng);
        keyGen.init(params);
        AsymmetricCipherKeyPair keypair = keyGen.generateKeyPair();
        AsymmetricKeyParameter priv = keypair.getPrivate();
        ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) priv;
        BigInteger privateKeyInt = privateKeyParams.getD();
        return pubKeyFromPrivate(privateKeyInt);
    }

    /**
     * Derives a public key from a private key.
     * 
     * @param privateKeyHex The hex string of the private key.
     * @return The hex string of the derived public key.
     */
    public static String pubKeyFromPrivate(String privateKeyHex) {
        BigInteger privateKeyInt = new BigInteger(privateKeyHex, 16);
        return pubKeyFromPrivate(privateKeyInt).getPublicKey();
    }

    /**
     * Derives an account ID from a private key. The derived account ID is the
     * base58 encoding of the ripemd160 hash of the sha256 hash of the public key.
     * <p>
     * When using with Fluree, it is common to express this as
     * "did:fluree:{accountID}". e.g.
     * "did:fluree:TeyBobG4LruuWaS7JkHwCnPAsgmFGwTMcPC"
     * </p>
     * 
     * @param privateKeyHex The hex string of the private key.
     * @return The account ID.
     * @throws Exception If an error occurs during account ID derivation.
     */
    public static String accountIdFromPrivateKey(String privateKeyHex) throws Exception {

        String publicKey = pubKeyFromPrivate(privateKeyHex);

        return accountIdFromPublicKey(publicKey);
    }

    /**
     * Derives an account ID from a public key. The derived account ID is the base58
     * encoding of the ripemd160 hash of the sha256 hash of the public key.
     * <p>
     * When using with Fluree, it is common to express this as
     * "did:fluree:{accountID}". e.g.
     * "did:fluree:TeyBobG4LruuWaS7JkHwCnPAsgmFGwTMcPC"
     * </p>
     * 
     * @param publicKey The hex string of the public key.
     * @return The account ID.
     * @throws Exception If an error occurs during account ID derivation.
     */
    public static String accountIdFromPublicKey(String publicKey) throws NoSuchAlgorithmException {
        byte[] pubKeyBytes = Signature.x962Decode(publicKey, secp256k1).getEncoded(true);
        byte[] sha256Bytes = sha256(pubKeyBytes);
        byte[] ripemdBytes = ripemd160(sha256Bytes);
        byte[] versionBytes = new byte[] { 0x0F, 0x02 };
        byte[] prefixedBytes = new byte[versionBytes.length + ripemdBytes.length];
        System.arraycopy(versionBytes, 0, prefixedBytes, 0, versionBytes.length);
        System.arraycopy(ripemdBytes, 0, prefixedBytes, versionBytes.length, ripemdBytes.length);
        byte[] checksum = sha256(sha256(prefixedBytes));
        byte[] bytes = new byte[prefixedBytes.length + 4];
        System.arraycopy(prefixedBytes, 0, bytes, 0, prefixedBytes.length);
        System.arraycopy(checksum, 0, bytes, prefixedBytes.length, 4);
        return Base58.encode(bytes);
    }

    /**
     * Produces a SHA-256 hash of the input data.
     * 
     * @param data
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    // -----------------------
    // Private helper methods
    // -----------------------

    private static String recoverPublicKey(String signingInput, String signature) throws NoSuchAlgorithmException {
        byte[] inputBytes = signingInput.getBytes(StandardCharsets.UTF_8);
        byte[] hash = sha256(inputBytes);
        try {
            return Utils.recoverPublicKeyFromHash(hash, signature);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Error recovering public key from hash and signature");
        }
    }

    private static String base64ToString(String base64String) {
        byte[] decodedBytes = Base64.getUrlDecoder().decode(base64String);
        return new String(decodedBytes);
    }

    private static Keypair pubKeyFromPrivate(BigInteger privateKeyInt) {
        if (!validPrivate(privateKeyInt)) {
            throw new IllegalArgumentException(
                    "Invalid private key. Must be convertible to big integer and >= 1, <= curve modulus.");
        }
        ECPoint publicKey = secp256k1.getG().multiply(privateKeyInt).normalize();
        return new Keypair(privateKeyInt, publicKey);
    }

    private static boolean validPrivate(BigInteger privateKeyInt) {
        BigInteger modulus = secp256k1.getN();
        return privateKeyInt.compareTo(BigInteger.ONE) >= 0 && privateKeyInt.compareTo(modulus) <= 0;
    }

    private static byte[] ripemd160(byte[] data) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(data, 0, data.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    private static HMacDSAKCalculator getKCalculator(ECDomainParameters ecParams, BigInteger privateKeyInt,
            byte[] data) {

        BigInteger n = ecParams.getN();
        int expectedLength = (n.bitLength()) / 8;

        if (data.length != expectedLength) {
            throw new IllegalArgumentException("Message length must be equal to " + expectedLength);
        }

        HMacDSAKCalculator kCalculator = new HMacDSAKCalculator(new SHA256Digest());

        kCalculator.init(n, privateKeyInt, data);

        return kCalculator;
    }

    private static String signWithSecp256k1(String data, String privateKeyHex) throws Exception {
        BigInteger privateKeyInt = new BigInteger(privateKeyHex, 16);
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
                params.getH());

        byte[] sha256Data = sha256(data.getBytes(StandardCharsets.UTF_8));

        HMacDSAKCalculator rng = getKCalculator(ecParams, privateKeyInt, sha256Data);

        BigInteger n = ecParams.getN();

        BigInteger z = new BigInteger(1, sha256Data);

        int l = n.bitLength();

        if (sha256Data.length != l / 8) {
            throw new IllegalArgumentException("Hash should have the same number of bytes as the curve modulus");
        }

        Signature signature = new Signature(ecParams, privateKeyInt, rng, n, z);

        int recoveryByte = signature.computeRecoveryByte();

        String derEncodedSignature = signature.getDEREncodedSignature(recoveryByte);

        return derEncodedSignature;
    }

    private static String base64UrlEncode(String data) {
        return Base64.getUrlEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8)).replace("=", "");
    }

}