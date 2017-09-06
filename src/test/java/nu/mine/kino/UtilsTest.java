/******************************************************************************
 * Copyright (c) 2014 Masatomi KINO and others. 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * Contributors:
 *      Masatomi KINO - initial API and implementation
 * $Id$
 ******************************************************************************/
//作成日: 2017/08/18

package nu.mine.kino;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import nu.mine.kino.utils.JSONUtils;
import nu.mine.kino.utils.Utils;

/**
 * @author Masatomi KINO
 * @version $Revision$
 */
/**
 * @author Masatomi KINO
 * @version $Revision$
 */
public class UtilsTest {

    // JSON Web Key (JWK) Thumbprint
    // http://openid-foundation-japan.github.io/rfc7638.ja.html
    /**
     * kidの仕様について。kidは、必須プロパティで構成したJSON文字列のSha256ハッシュらしい。
     */
    @Test
    public void testJWK_kid_is_Sha256_001() {
        // kidの仕様について。JSON文字列のSha256ハッシュらしい。
        String expected_kid = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; // JSON内のkidの値
        try {
            // このJSONファイルは、RFCのサイトのサンプルのJWKファイル
            byte[] data = Files.readAllBytes(Paths.get("sample.json"));
            String actual_value = Base64
                    .encodeBase64URLSafeString(DigestUtils.sha256(data));
            System.out.printf("kid: %s\n", actual_value);
            assertThat(actual_value, is(expected_kid));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    // https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-rsa-signature
    // https://connect2id.com/products/nimbus-jose-jwt/examples/jwk-conversion
    /**
     * javaの標準ライブラリとconnect2idのnimbusライブラリの相互変換
     */
    @Test
    public void java2nimbus_and_nimbus2java_sample() {

        // Javaの世界 のKeyPairからはじめる
        Key[] keys = null;
        keys = createJavaAPIKey();
        RSAPublicKey publicKey = (RSAPublicKey) keys[0];
        RSAPrivateKey privateKey = (RSAPrivateKey) keys[1];
        // Javaの世界 以上

        // そのオブジェクトをnimbusのオブジェクトへ変換。keyIDなども付与
        // Convert to JWK format
        com.nimbusds.jose.jwk.RSAKey rsaKey = new RSAKey.Builder(publicKey)//
                .privateKey(privateKey)//
                .keyID(Utils.getRandomString())//
                .build();

        // あらためて、Javaの世界のオブジェクトへ戻す
        // Convert back to std Java interface
        try {
            RSAPublicKey convertedRSAPublicKey = rsaKey.toRSAPublicKey();
            RSAPrivateKey convertedRSAPrivateKey = rsaKey.toRSAPrivateKey();

            assertThat(convertedRSAPublicKey, is(publicKey));
            assertThat(convertedRSAPrivateKey, is(privateKey));

            java.security.PublicKey convertedPublicKey = rsaKey.toPublicKey();
            java.security.PrivateKey convertedPrivateKey = rsaKey
                    .toPrivateKey();

            assertThat(convertedPublicKey, is((PublicKey) publicKey));
            assertThat(convertedPrivateKey, is((PrivateKey) privateKey));

        } catch (JOSEException e) {
            fail(e.getMessage());
        }

    }

    @Test
    public void testJWKSet() {

        // Javaの世界 のKeyPairからはじめる
        Key[] keys = createJavaAPIKey();
        RSAPublicKey publicKey = (RSAPublicKey) keys[0];
        RSAPrivateKey privateKey = (RSAPrivateKey) keys[1];

        ////////
        // JavaのKeyPairから、JWKSetをつくる
        List<JWK> jwkList = new ArrayList<JWK>();
        jwkList.add(new RSAKey.Builder(publicKey)//
                .privateKey(privateKey)//
                .keyID(Utils.getRandomString())//
                .build());
        jwkList.add(new RSAKey.Builder(publicKey)//
                .privateKey(privateKey)//
                .keyID(Utils.getRandomString())//
                .build());
        JWKSet jwkSet = new JWKSet(jwkList);
        // JSON文字列として出力。多分そのままファイル保存すればJWKのファイルとしていけるモノと思われる
        System.out.println(jwkSet.toJSONObject(false).toJSONString());

    }

    @Test
    public void testPrintJWK() throws JsonProcessingException {

        Key[] keys = createJavaAPIKey();
        // 秘密キーと公開キーを表示
        for (Key key : keys) {
            String algo = key.getAlgorithm();
            String format = key.getFormat();
            byte[] bin = key.getEncoded();
            String encoded = Utils.encodeBase64URLSafeString(bin);
            System.out.println(
                    "algo=" + algo + "/format=" + format + "/key=" + encoded);
        }

        RSAPublicKey publicKey = (RSAPublicKey) keys[0];
        RSAPrivateKey privateKey = (RSAPrivateKey) keys[1];

        // RSAPublicKey publicKey = createPublicKey();
        // RSAPrivateKey privateKey = createPrivateKey();

        // そのオブジェクトをnimbusのオブジェクトへ変換。keyIDなども付与
        // Convert to JWK format
        RSAKey rsaKey = new RSAKey.Builder(publicKey)//
                .privateKey(privateKey)//
                .keyID(Utils.getRandomString())//
                .build();
        // JSON文字列として出力。多分そのままファイル保存すればJWKのファイルとしていけるモノと思われる
        System.out.println(JSONUtils.toPrettyStr(rsaKey));

    }

    
    /**
     * ターミナルのssh-keygen/opensllコマンドなどで作成した、公開鍵、秘密鍵を使ってJavaで暗号化・復号化するテスト。 
     */
    @Test
    public void testEncrypt_and_decrypt() {
        Key[] keys = createJavaAPIKeyFromFile();
        // opensslやssh-keygenによって作成された秘密鍵、公開鍵からJavaのprivate/public 鍵を作成するサンプル
        PublicKey publicKey = (PublicKey) keys[0];
        PrivateKey privateKey = (PrivateKey) keys[1];

        // 暗号化してファイル出力して、そのあと復号化してみた。
        String expected = "Hello World.\n";
        String output = "encrypted.out";
        writeEncryptedFile(expected, publicKey, new File(output));
        String result = readDecryptedFile(privateKey, new File(output));

        assertThat(result, is(expected));

    }

    // https://blog.ik.am/entries/327
    // http://unhurried.hatenablog.com/entry/openssl_java_rsa_key
    // $ openssl rsa -pubout \
    // -in sshkeygen -out public.der -outform DER
    // $ openssl pkcs8 -topk8 -nocrypt \
    // -in sshkeygen -out private.pk8 -outform DER
    private Key[] createJavaAPIKey() {
        // Javaの世界 のKeyPairからはじめる
        java.security.KeyPair keyPair = null;
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);
            keyPair = keyGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        // Javaの世界 以上
        return new Key[] { publicKey, privateKey };
    }

    private Key[] createJavaAPIKeyFromFile() {
        return new Key[] { createPublicKey(), createPrivateKey() };
    }

    private PrivateKey createPrivateKey() {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            byte[] keyBytes = Files.readAllBytes(Paths.get("private.pk8"));
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            PrivateKey privateKey = factory.generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private PublicKey createPublicKey() {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            byte[] keyBytes = Files.readAllBytes(Paths.get("public.der"));
            X509EncodedKeySpec keyspec = new X509EncodedKeySpec(keyBytes);
            PublicKey publicKey = factory.generatePublic(keyspec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * 公開鍵で暗号化。基本的に、
     * 
     * echo "Hello World." | openssl rsautl -encrypt -pubin -inkey \
     * sshkeygen.pub.pem > encrypted.out
     *
     * とおなじになるハズ(今んとこならないが、、、、。)
     * 
     * http://www.masatom.in/pukiwiki/Linux/%B8%F8%B3%AB%B8%B0%B0%C5%B9%E6/
     * 
     * @param expected
     * @param publicKey
     * @param file
     */
    private void writeEncryptedFile(String expected, PublicKey publicKey,
            File file) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] bytes = cipher.doFinal(expected.getBytes());
            Files.write(Paths.get(file.getAbsolutePath()), bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchPaddingException e) {
            throw new IllegalArgumentException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalArgumentException(e);
        } catch (BadPaddingException e) {
            throw new IllegalArgumentException(e);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * 秘密鍵で復号する。基本的に、
     * 
     * openssl rsautl -decrypt -inkey sshkeygen -in encrypted.out
     * 
     * とおなじハズ。上記Javaメソッドで作成したファイルは、Javaでも復号出来たし、プロンプトからでも復号出来た。
     * @param privateKey
     * @param file
     * @return
     */
    private String readDecryptedFile(PrivateKey privateKey, File file) {
        try {
            byte[] encrypted = Files
                    .readAllBytes(Paths.get(file.getAbsolutePath()));
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, "UTF-8");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchPaddingException e) {
            throw new IllegalArgumentException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalArgumentException(e);
        } catch (BadPaddingException e) {
            throw new IllegalArgumentException(e);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    // jwkファイルから、オブジェクトを生成する。
    // https://connect2id.com/products/nimbus-jose-jwt/generator
    @Test
    public void test2() throws KeyLengthException, JOSEException,
            ParseException, NoSuchAlgorithmException, IOException {

        // ファイルからJWKSetを生成。秘密鍵が書いてるjsonなのでisPrivateはtrueのはず
        JWKSet jwkSet = JWKSet.load(new File("jwk.json"));
        System.out.println(jwkSet);
        String keyID = "1";

        JWK key = jwkSet.getKeyByKeyId(keyID);
        RSAKey rsaKey = RSAKey.parse(key.toJSONObject());
        assertThat(rsaKey.isPrivate(), is(true));

        jwkSet = jwkSet.toPublicJWKSet();
        System.out.println(jwkSet);
        key = jwkSet.getKeyByKeyId(keyID);
        rsaKey = RSAKey.parse(key.toJSONObject());
        assertThat(rsaKey.isPrivate(), is(false));

        // ファイルからJWKSetを生成。公開鍵のみのjsonなので、isPrivateはfalseのはず
        jwkSet = JWKSet.load(new File("jwk_public_only.json"));
        System.out.println(jwkSet);

        key = jwkSet.getKeyByKeyId(keyID);
        rsaKey = RSAKey.parse(key.toJSONObject());
        assertThat(rsaKey.isPrivate(), is(false));

    }

    // JWKファイルから秘密鍵、公開鍵を取得して、署名。
    // JWKファイルから公開鍵を取得して署名検証、というサンプル
    // https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-rsa-signature
    @Test
    public void test3() throws KeyLengthException, JOSEException,
            ParseException, NoSuchAlgorithmException, IOException {

        String data = "Hello world.";

        JWKSet jwkSet = JWKSet.load(new File("jwk.json"));
        // System.out.println(jwkSet);
        String keyID = "1";

        JWK key = jwkSet.getKeyByKeyId(keyID);
        RSAKey rsaKey = RSAKey.parse(key.toJSONObject());

        JWSSigner signer = new RSASSASigner(rsaKey);

        // Prepare JWS object with simple string as payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyID).build(),
                new Payload(data));

        // Compute the RSA signature
        jwsObject.sign(signer);
        String s = jwsObject.serialize();

        System.out.printf("result:\n %s\n", s);

        jwkSet = JWKSet.load(new File("jwk_public_only.json"));
        key = jwkSet.getKeyByKeyId(keyID);

        JWSVerifier verifier = new RSASSAVerifier(rsaKey);

        SignedJWT decodeObject = SignedJWT.parse(s);
        assertThat(decodeObject.verify(verifier), is(true));

    }

    // 秘密鍵がないJWKで署名クラスを作ったので例外が発生するはず。
    // https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-rsa-signature
    @Test
    public void test4() throws IOException, ParseException {

        JWKSet jwkSet = JWKSet.load(new File("jwk_public_only.json"));
        String keyID = "1";

        JWK key = jwkSet.getKeyByKeyId(keyID);
        RSAKey rsaKey = RSAKey.parse(key.toJSONObject());
        try {
            JWSSigner signer = new RSASSASigner(rsaKey);
            fail("秘密鍵がないJWKで署名クラスを作ったのに、例外が発生しなかった");
        } catch (JOSEException e) {
        }
    }

    @Test
    public void jwks_endpoint_test() throws IOException, ParseException {
        String url = "https://auth.login.yahoo.co.jp/yconnect/v2/jwks";

        // nimbus
        // JWKSet -> JWK -> RSAKey
        JWKSet jwkSet = JSONUtils.getJWKSet(url);
        String keyID = "0cc175b9c0f1b6a831c399e269772661";

        JWK key = jwkSet.getKeyByKeyId(keyID);
        RSAKey rsaKey = RSAKey.parse(key.toJSONObject());

        try {
            JWSSigner signer = new RSASSASigner(rsaKey);
            fail("秘密鍵がないJWKで署名クラスを作ったのに、例外が発生しなかった");
        } catch (JOSEException e) {
        }

        try {
            JWSVerifier verifier = new RSASSAVerifier(rsaKey);
        } catch (JOSEException e) {
            fail("秘密鍵がないJWKでも署名検証クラスは作れるはずなのに、エラーになってしまった。");
        }

    }

}
