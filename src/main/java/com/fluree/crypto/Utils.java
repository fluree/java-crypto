package com.fluree.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;

class Utils {
    static byte[] hexToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    static String recoverPublicKeyFromHash(byte[] hash, String signature) throws IOException {
        // Implement logic to recover public key from hash and signature
        BigInteger[] result = Signature.decodeDERSignature(signature);

        int recId = result[0].intValue();
        BigInteger r = result[1];
        BigInteger s = result[2];
        return Signature.ecRecover(hash, recId, r, s);
    }

    static String padToLength(String input, int length) {
        int padLen = length - input.length();
        if (padLen > 0) {
            return String.join("", Collections.nCopies(padLen, "0")) + input;
        }
        return input;
    }

    static String byteArrayToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
