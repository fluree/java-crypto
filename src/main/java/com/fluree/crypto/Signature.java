package com.fluree.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

class Signature {
    private final BigInteger r;
    private final BigInteger s;
    private final BigInteger s_;
    private final ECPoint kp;
    private final ECDomainParameters ecParams;

    private static final byte[] VALID_RECOVERY_BYTES = new byte[] { 0x1b, 0x1c, 0x1d, 0x1e };

    // -----------------------
    // Constructors
    // -----------------------

    Signature(ECDomainParameters ecParams, BigInteger privateBn, HMacDSAKCalculator rng, BigInteger n, BigInteger z) {
        BigInteger r = BigInteger.ZERO;
        BigInteger s = BigInteger.ZERO;
        BigInteger s_ = BigInteger.ZERO;
        ECPoint kp = null;

        while (r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO)) {
            BigInteger k = rng.nextK();

            kp = ecParams.getG().multiply(k).normalize();
            r = kp.getXCoord().toBigInteger().mod(n);

            s_ = k.modInverse(n).multiply(r.multiply(privateBn).add(z)).mod(n);

            // s (if (< (+ s_ s_) n) s_ (.subtract n s_))]
            if (s_.add(s_).compareTo(n) < 0) {
                s = s_;
            } else {
                s = n.subtract(s_);
            }
        }

        this.r = r;
        this.s = s;
        this.s_ = s_;
        this.kp = kp;
        this.ecParams = ecParams;
    }

    int computeRecoveryByte() {
        BigInteger n = this.ecParams.getN();

        boolean isBigR = this.r.compareTo(n) >= 0;

        boolean isBigS = (this.s_.add(this.s_)).compareTo(n) >= 0;

        boolean yIsOdd = this.kp.getYCoord().toBigInteger().testBit(0);

        int result = 0x1B;

        if (isBigS != yIsOdd) {
            result += 1;
        }
        if (isBigR) {
            result += 2;
        }
        return result;
    }

    String getDEREncodedSignature(int recId) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            DERSequenceGenerator derGen = new DERSequenceGenerator(bos);
            derGen.addObject(new ASN1Integer(this.r));
            derGen.addObject(new ASN1Integer(this.s));
            derGen.close();
        } catch (Exception e) {
            throw new IOException("Unable to encode signature: " + e.getMessage());
        }

        byte[] result = bos.toByteArray();

        byte[] withRecover = new byte[result.length + 1];
        withRecover[0] = (byte) recId;
        System.arraycopy(result, 0, withRecover, 1, result.length);

        return IntStream.range(0, withRecover.length).mapToObj(i -> String.format("%02x", withRecover[i]))
                .collect(Collectors.joining());

    }

    static BigInteger[] decodeDERSignature(String signature) throws IOException {
        String asn1 = signature.toLowerCase();
        String firstByteStr = asn1.substring(0, 2);
        byte firstByte = (byte) Integer.parseInt(firstByteStr, 16);
        if (IntStream.range(0, VALID_RECOVERY_BYTES.length).anyMatch(i -> VALID_RECOVERY_BYTES[i] == firstByte)) {
            List<BigInteger> result = new ArrayList<>();
            result.add(BigInteger.valueOf(firstByte));
            BigInteger[] decoded = decodeDERStandard(asn1.substring(2));
            result.addAll(Arrays.asList(decoded));
            return result.toArray(new BigInteger[0]);
        }
        if (firstByte == 0x30) {
            return decodeDERStandard(asn1);
        } else {
            throw new RuntimeException(
                    "Input must start with the code 30, or start with a recovery code (either 1b, 1c, 1d, or 1e)");
        }

    }

    static String ecRecover(byte[] hash, int recoveryByte, BigInteger r, BigInteger s) {
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");

        ECDomainParameters secp256k1 = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(),
                params.getH());

        if (recoveryByte < 0x1B || recoveryByte > 0x1E) {
            throw new RuntimeException(
                    "Recovery byte should be between 0x1B and 0x1E. Provided: " + String.format("%x", recoveryByte));
        }

        int l = secp256k1.getN().bitLength() / 8;
        if (hash.length != l) {
            throw new RuntimeException("Hash should have " + l + " bytes, but had " + hash.length + ".");
        }

        boolean yEven = (recoveryByte - 0x1B) % 2 == 0;
        boolean isSecondKey = (recoveryByte - 0x1B) >> 1 % 2 == 1;

        BigInteger n = secp256k1.getN();
        BigInteger xCoord = isSecondKey ? r.add(n) : r;
        String point = computePoint(yEven, xCoord, secp256k1);
        ECPoint R = x962Decode(point, secp256k1);
        BigInteger rInv = r.modInverse(n);
        BigInteger hashBi = new BigInteger(1, hash);
        BigInteger eInv = n.subtract(hashBi);

        ECPoint sumOfTwoMultiplies = ECAlgorithms.sumOfTwoMultiplies(secp256k1.getG(), eInv, R, s).multiply(rInv)
                .normalize();
        return formatPublicKey(sumOfTwoMultiplies);

    }

    static String x962Encode(String x, String y, boolean isCompressed) {
        if (!isCompressed) {
            return "04" + Utils.padToLength(x, 64) + Utils.padToLength(y, 64);
        } else {
            BigInteger yBigInt = new BigInteger(y, 16);
            boolean yEven = yBigInt.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO);
            if (yEven) {
                return "02" + Utils.padToLength(x, 64);
            } else {
                return "03" + Utils.padToLength(x, 64);
            }
        }
    }

    static ECPoint x962Decode(String publicKey, ECDomainParameters ecParams) {
        String firstByte = publicKey.substring(0, 2);
        if (!Arrays.asList("02", "03", "04").contains(firstByte)) {
            throw new RuntimeException(
                    "X9.62 encoded public key must have a first byte of 0x02, 0x03 or 0x04. Provided: " + publicKey);
        }
        if (Arrays.asList("02", "03").contains(firstByte)) {
            return x962HexCompressedDecode(publicKey, ecParams);
        } else if (firstByte.equals("04")) {
            return x962HexUncompressedDecode(publicKey, ecParams);
        } else {
            throw new RuntimeException("Invalid encoding on public key: " + publicKey);
        }
    }

    // -----------------------
    // Private methods
    // -----------------------

    private static BigInteger[] decodeDERStandard(String asn1) throws IOException {
        if (!asn1.substring(0, 2).equals("30")) {
            throw new RuntimeException("Invalid DER signature");
        }
        byte[] signature = Utils.hexToByteArray(asn1);
        try (ASN1InputStream decoder = new ASN1InputStream(new ByteArrayInputStream(signature))) {

            ASN1Sequence sequence = (ASN1Sequence) decoder.readObject();

            ASN1Integer r = (ASN1Integer) sequence.getObjectAt(0);
            ASN1Integer s = (ASN1Integer) sequence.getObjectAt(1);

            return new BigInteger[] { r.getValue(), s.getValue() };
        }

    }

    private static String formatPublicKey(ECPoint point) {
        String x = point.getAffineXCoord().toBigInteger().toString(16);
        String y = point.getAffineYCoord().toBigInteger().toString(16);
        return x962Encode(x, y, true);
    }

    private static ECPoint x962HexCompressedDecode(String encodedKey, ECDomainParameters curve) {
        byte[] x = Utils.hexToByteArray(encodedKey);
        ECPoint point = curve.getCurve().decodePoint(x);
        BigInteger xCoord = point.getXCoord().toBigInteger();
        BigInteger yCoord = point.getYCoord().toBigInteger();
        return curve.getCurve().createPoint(xCoord, yCoord).normalize();
    }

    private static ECPoint x962HexUncompressedDecode(String encodedKey, ECDomainParameters curve) {
        int size = encodedKey.length() - 2;
        String x = encodedKey.substring(2, 2 + size);
        String y = encodedKey.substring(2 + size);
        BigInteger xCoord = new BigInteger(x, 16);
        BigInteger yCoord = new BigInteger(y, 16);
        return curve.getCurve().createPoint(xCoord, yCoord).normalize();
    }

    public static String computePoint(boolean yEven, BigInteger x, ECDomainParameters ecParams) {
        int l = ecParams.getN().bitLength() / 8;
        byte[] raw = x.toByteArray();
        byte[] input = new byte[l];
        if (l == raw.length) {
            System.arraycopy(raw, 0, input, 0, l);
        } else if (l < raw.length) {
            // (drop-while zero? raw)
            int i = 0;
            while (i < raw.length && raw[i] == 0) {
                i++;
            }
            System.arraycopy(raw, i, input, 0, l);
        } else if (l > raw.length) {
            byte[] out = new byte[l];
            System.arraycopy(raw, 0, out, l - raw.length, raw.length);
            System.arraycopy(out, 0, input, 0, l);
        }

        byte yByte = (byte) (yEven ? 0x02 : 0x03);
        byte[] result = new byte[l + 1];
        result[0] = yByte;
        System.arraycopy(input, 0, result, 1, l);
        String hex = Utils.byteArrayToHex(result);
        return Utils.padToLength(hex, 64);
    }

    public static boolean verify(String pubkey, String message, String signature) throws NoSuchAlgorithmException {
        byte[] hash = Crypto.sha256(message.getBytes(StandardCharsets.UTF_8));
        return verifySignatureFromHash(pubkey, hash, signature);

    }

    public static boolean verifySignatureFromHash(String key, byte[] hash, String signature) {
        String head1 = signature.substring(0, 2);
        String head2 = signature.substring(2, 4);
        if (Arrays.asList("1b", "1c", "1d", "1e").contains(head1) && head2.equals("30")) {
            try {
                return key.equals(Utils.recoverPublicKeyFromHash(hash, signature));
            } catch (IOException e) {
                throw new RuntimeException("Error recovering public key from hash: " + e.getMessage());
            }
        } else {
            throw new RuntimeException("Unknown signature header");
        }
    }
}