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

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;
import org.junit.Test;

/**
 * @author Masatomi KINO
 * @version $Revision$
 */
public class ShaXXTest {

    // Apache Commons Codec のsha256メソッドの確認
    @Test
    public void testDigestUtils001() {
        String data = "Hello, world!";
        try {
            String result01 = Base64.encodeBase64URLSafeString(sha256(data));
            String result02 = Base64
                    .encodeBase64URLSafeString(DigestUtils.sha256(data));
            System.out.println(result01);
            System.out.println(result02);

            assertThat(result01, is(result02));
        } catch (Exception e) {
            fail(e.getMessage());
        }

    }

    /**
     * SHA-256によるハッシュ値(byte[])を生成する。
     * 
     * @param data
     * @return
     */
    private byte[] sha256(String data) {
        String algorithm = "SHA-256";
        // String algorithm = MessageDigestAlgorithms.SHA_256.toString();
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            return digest.digest(data.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    // Apache Commons Codec のhmacSha256メソッドの確認
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

    /**
     * HmacSHA256による、共通鍵暗号方式を用いた、ハッシュ値(byte[])を生成する。
     * 
     * @param secretKey
     * @param data
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static byte[] hmacSha256(String secretKey, String data)
            throws InvalidKeyException {
        String algorithm = "HmacSHA256";
        // String algorithm = HmacAlgorithms.HMAC_SHA_256.toString();

        SecretKey key = new SecretKeySpec(secretKey.getBytes(), algorithm);
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(key);
            mac.update(data.getBytes("UTF-8"));
            return mac.doFinal();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
