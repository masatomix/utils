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
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.HmacUtils;
import org.junit.Test;

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
public class UtilsTest {

    @Test
    public void hoge() throws IOException, ParseException {
        String url = "https://auth.login.yahoo.co.jp/yconnect/v2/jwks";

        // nimbus
        // JWKSet -> JWK -> RSAKey
        JWKSet jwkSet = JSONUtils.getJWKSet(url);
        System.out.println(JSONUtils.toPrettyStr(jwkSet));
        String keyID = "0cc175b9c0f1b6a831c399e269772661";

        JWK key = jwkSet.getKeyByKeyId(keyID);
        RSAKey rsaKey = RSAKey.parse(key.toJSONObject());

    }

    @Test
    public void testHmacUtils001() {

        String data = "Hello, world!";
        String key = "aaaaaaaaaabbbbbbaaaaaaaaaabbbbbb"; // <-256bitの共通鍵

        try {
            String result01 = Base64
                    .encodeBase64URLSafeString(hmacSha256(key, data));
            String result02 = Base64
                    .encodeBase64URLSafeString(HmacUtils.hmacSha256(key, data));
            System.out.println(result01);
            System.out.println(result02);

            assertThat(result01, is(result02));
        } catch (Exception e) {
            fail(e.getMessage());
        }

    }

    private static byte[] hmacSha256(String secretKey, String data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        String algorithm = "HmacSHA256";
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), algorithm);

        Mac mac = Mac.getInstance(algorithm);
        mac.init(key);
        mac.update(data.getBytes());

        return mac.doFinal();
    }

    // https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-rsa-signature
    // https://connect2id.com/products/nimbus-jose-jwt/examples/jwk-conversion
    @Test
    public void java2nimbus_and_nimbus2java_sample() {

        // Javaの世界 のKeyPairからはじめる
        java.security.KeyPair keyPair = null;
        try {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(1024);
            keyPair = keyGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
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
            java.security.PublicKey convertedPublicKey = rsaKey.toPublicKey();
            java.security.PrivateKey convertedPrivateKey = rsaKey
                    .toPrivateKey();

            // これら↓は、RSAがつかない上のサブクラスになっているだけ。
            RSAPublicKey convertedRSAPublicKey = rsaKey.toRSAPublicKey();
            RSAPrivateKey convertedRSAPrivateKey = rsaKey.toRSAPrivateKey();

            assertThat(convertedPublicKey, is((PublicKey) publicKey));
            assertThat(convertedPrivateKey, is((PrivateKey) privateKey));

            assertThat(convertedRSAPublicKey, is(publicKey));
            assertThat(convertedRSAPrivateKey, is(privateKey));
        } catch (JOSEException e) {
            fail(e.getMessage());
        }

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

}
