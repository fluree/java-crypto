# Fluree Crypto Java Library

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Java library that provides cryptographic utilities for generating keypairs, signing and verifying JSON Web Signatures (JWS), and deriving account IDs for use with [Fluree](https://docs.flur.ee/).

## Features

- [**Generate Keypair**](#1-generate-keypair): Generate a secp256k1 keypair.
- [**Create JWS**](#2-create-jws): Sign a payload using a private key and create a JWS.
- [**Verify JWS**](#3-verify-jws): Verify a JWS and retrieve the payload and public key used to sign it.
- [**Derive Public Key**](#4-derive-public-key-from-private-key): Derive a public key from a private key.
- [**Derive Account ID from Private Key**](#5-derive-account-id-from-private-key): Derive a Fluree-compatible account ID from a private key.
- [**Derive Account ID from Public Key**](#6-derive-account-id-from-public-key): Derive a Fluree-compatible account ID from a public key.

## Installation

### Maven

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.fluree</groupId>
    <artifactId>crypto</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle

Add the following dependency to your `build.gradle`:

```groovy
implementation 'com.fluree:crypto:1.0.0'
```

## Usage

### 1. **Generate Keypair**

You can generate a secp256k1 keypair using the `generateKeyPair` method.

```java
import com.fluree.crypto.Crypto;
import com.fluree.crypto.Keypair;

public class Example {
    public static void main(String[] args) throws Exception {
        Keypair keypair = Crypto.generateKeyPair();
        System.out.println("Private Key: " + keypair.getPrivateKey());
        System.out.println("Public Key: " + keypair.getPublicKey());
    }
}
```

### 2. **Create JWS**

Sign a payload using a private key and create a JWS.

```java
import com.fluree.crypto.Crypto;

public class Example {
    public static void main(String[] args) throws Exception {
        Keypair keypair = Crypto.generateKeyPair();
        String privateKey = keypair.getPrivateKey();
        String payload = "{\"foo\":\"bar\"}";
        String jws = Crypto.createJws(payload, privateKey);
        System.out.println("JWS: " + jws);
    }
}
```

### 3. **Verify JWS**

Verify a JWS and retrieve the payload and public key used to sign it.

```java
import com.fluree.crypto.Crypto;
import java.util.HashMap;

public class Example {
    public static void main(String[] args) throws Exception {
        Keypair keypair = Crypto.generateKeyPair();
        String privateKey = keypair.getPrivateKey();
        String publicKey = keypair.getPublicKey();
        String payload = "{\"foo\":\"bar\"}";
        String jws = Crypto.createJws(payload, privateKey);
        HashMap<String, String> result = Crypto.verifyJws(jws);
        System.out.println("Payload: " + result.get("payload"));
        System.out.println("Public Key: " + result.get("pubkey"));
        Assert.assertEquals(result.get("payload"), payload);
        Assert.assertEquals(result.get("pubkey"), publicKey);
    }
}
```

### 4. **Derive Public Key from Private Key**

Derive the public key from a private key in hexadecimal format.

```java
import com.fluree.crypto.Crypto;

public class Example {
    public static void main(String[] args) {
        Keypair keypair = Crypto.generateKeyPair();
        String privateKey = keypair.getPrivateKey();
        String publicKey = Crypto.pubKeyFromPrivate(privateKey);
        System.out.println("Public Key: " + publicKey);
    }
}
```

### 5. **Derive Account ID from Private Key**

Derive a Fluree-compatible account ID from a private key.

```java
import com.fluree.crypto.Crypto;

public class Example {
    public static void main(String[] args) throws Exception {
        Keypair keypair = Crypto.generateKeyPair();
        String privateKey = keypair.getPrivateKey();
        String accountId = Crypto.accountIdFromPrivateKey(privateKey);
        System.out.println("Account ID: " + accountId);
    }
}
```

### 6. **Derive Account ID from Public Key**

Derive a Fluree-compatible account ID from a public key.

```java
import com.fluree.crypto.Crypto;

public class Example {
    public static void main(String[] args) throws Exception {
        Keypair keypair = Crypto.generateKeyPair();
        String privateKey = keypair.getPrivateKey();
        String publicKey = Crypto.pubKeyFromPrivate(privateKey);
        String accountId = Crypto.accountIdFromPublicKey(publicKey);
        System.out.println("Account ID: " + accountId);
    }
}
```

## Methods Overview

### `createJws(String payload, String privateKeyHex)`

- **Description**: Creates a JWS (JSON Web Signature) using the provided payload and private key.
- **Parameters**:
  - `payload`: The stringified payload to sign.
  - `privateKeyHex`: The private key used to sign the payload (in hexadecimal format).
- **Returns**: A JWS string.
- **Throws**: Exception if the JWS creation fails.

### `verifyJws(String jwsString)`

- **Description**: Verifies a JWS and returns a map containing the payload and public key.
- **Parameters**:
  - `jwsString`: The JWS string to verify.
- **Returns**:
  - A `HashMap<String, String>` containing the `payload` and `pubkey`.
  - `null` if the verification fails.

### `generateKeyPair()`

- **Description**: Generates a secp256k1 keypair.
- **Returns**: A `Keypair` object containing the public and private keys.
- **Throws**: Exception if keypair generation fails.

### `pubKeyFromPrivate(String privateKeyHex)`

- **Description**: Derives the public key from a private key.
- **Parameters**:
  - `privateKeyHex`: The private key (in hexadecimal format).
- **Returns**: The public key (in hexadecimal format).

### `accountIdFromPrivateKey(String privateKeyHex)`

- **Description**: Derives a Fluree-compatible account ID from a private key.
- **Parameters**:
  - `privateKeyHex`: The private key (in hexadecimal format).
- **Returns**: The account ID (in base58 encoding).
- **Throws**: Exception if the account ID derivation fails.

### `accountIdFromPublicKey(String publicKey)`

- **Description**: Derives a Fluree-compatible account ID from a public key.
- **Parameters**:
  - `publicKey`: The public key (in hexadecimal format).
- **Returns**: The account ID (in base58 encoding).
- **Throws**: Exception if the account ID derivation fails.

## Development

### Building the Project

To build the project, use Maven:

```bash
mvn clean install
```

### Running Tests

To run tests, use:

```bash
mvn test
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

---

Happy coding! 🌟
