package com.fluree.crypto;

import org.junit.Test;

import static org.junit.Assert.*;

import java.util.HashMap;

public class JwsUtilsTest {

    @Test
    public void testGenerateKeyPair() {
        try {
            Keypair keyPair = Crypto.generateKeyPair();
            assertNotNull(keyPair.getPrivateKey());
            assertNotNull(keyPair.getPublicKey());
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testCreateJWS() {
        String s = "abcdefg";
        String headerb64 = "eyJhbGciOiJFUzI1NkstUiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19";
        String payloadb64 = "YWJjZGVmZw";
        String expectedSig = "MWMzMDQ1MDIyMTAwOTcxOWM0M2NlM2U3OTIzYjcyNTEzZTM0MWMxMzAxZjI1ODA2NmY3NDIzZDI3M2VjNGY3MjMzODFlNzdiMTA3OTAyMjAyMzQ3YjA1YjVlMWQ5NDVmYjkxNzgxYzg2M2MxNjlkOGE4NzhmOGNjZjg4Njk3MjBmZWUzM2I4YTA2ZTIwNjg2";
        String privateKey = "42827e1ee6580a3cd367f31c4af2528db7269b8ea30c6cdff0af6e52d0c4480a";
        try {
            String jws = Crypto.createJws(s, privateKey);
            String expectedResult = headerb64 + "." + payloadb64 + "." + expectedSig;
            assertEquals(expectedResult, jws);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testVerifyJWS() {
        String s = "abcdefg";
        String privateKey = "42827e1ee6580a3cd367f31c4af2528db7269b8ea30c6cdff0af6e52d0c4480a";
        try {
            String jws = Crypto.createJws(s, privateKey);
            HashMap<String, String> result = Crypto.verifyJws(jws);
            assertNotNull(result.get("payload"));
            assertNotNull(result.get("pubkey"));
            assertEquals(s, result.get("payload"));
        } catch (Exception e) {
            fail(e.getMessage());
        }

    }

    @Test
    public void testPublicKeyFromPrivate() {
        try {
            Keypair keypair = Crypto.generateKeyPair();
            String publicKey = keypair.getPublicKey();
            String derivedPublicKey = Crypto.pubKeyFromPrivate(keypair.getPrivateKey());
            assertEquals(publicKey, derivedPublicKey);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void rTest() {
        String priv = "b93db2826671c5068cc365670be9ab8f79464e98953ae8ae93181c360100ae9a";
        String expectedPub = "02f28c6b4dda361691ef29677fef662f9a48bf867c6b3e3a643eebf8f5e633e010";
        try {
            String pub = Crypto.pubKeyFromPrivate(priv);
            assertEquals(expectedPub, pub);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testMultipleRandomJWSAndVerification() {
        String[] samplePayloads = {
                // Simple string payloads
                "abcdefg", "1234567890", "hello world", "jws testing",

                // JSON-like string payloads (as strings)
                "{\"foo\": 1, \"bar\": \"baz\", \"object\": {\"foo\": \"bar\"}}",
                "{\"username\": \"testuser\", \"email\": \"test@example.com\", \"active\": true}",
                "{\"data\": [1, 2, 3, 4, 5]}", "{\"type\": \"event\", \"timestamp\": \"2024-09-20T12:34:56Z\"}",
                "{\"settings\": {\"theme\": \"dark\", \"notifications\": {\"email\": true, \"sms\": false}}}",
                "{\"foo\": null, \"count\": 100, \"items\": [{\"id\": 1, \"name\": \"item1\"}, {\"id\": 2, \"name\": \"item2\"}]}",
                "{\"nested\": {\"level1\": {\"level2\": {\"key\": \"value\"}}}}",
                "{\"message\": \"test payload with special characters !@#$%^&*()_+{}|:\"<>?\"}",
                "{\"unicode\": \"测试\", \"emoji\": \"😊\"}",
                "{\"longString\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
                "{\"array\": [\"item1\", \"item2\", \"item3\"], \"count\": 3}" };
        try {
            Keypair keypair = Crypto.generateKeyPair();
            String privateKey = keypair.getPrivateKey();
            String publicKey = keypair.getPublicKey();
            for (int i = 0; i < samplePayloads.length; i++) {
                String s = samplePayloads[i];
                try {
                    String jws = Crypto.createJws(s, privateKey);
                    HashMap<String, String> result = Crypto.verifyJws(jws);
                    assertNotNull(result.get("payload"));
                    assertNotNull(result.get("pubkey"));
                    assertEquals(s, result.get("payload"));
                    assertEquals(publicKey, result.get("pubkey"));
                } catch (Exception e) {
                    fail(e.getMessage());
                }
            }
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testGetAccountIdFromPublicKey() {
        String publicKey = "03eba6a79dbdef8de9e588b9c3c45860c921dca715b6260fef33261c061e21c0c1";
        String expectedAccountId = "TeyBobG4LruuWaS7JkHwCnPAsgmFGwTMcPC";
        try {
            String accountId = Crypto.accountIdFromPublicKey(publicKey);
            assertEquals(expectedAccountId, accountId);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }
}
