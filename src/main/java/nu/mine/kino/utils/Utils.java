/******************************************************************************
 * Copyright (c) 2010 Masatomi KINO and others. 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * Contributors:
 *      Masatomi KINO - initial API and implementation
 * $Id$
 ******************************************************************************/
//作成日: 2017/07/23

package nu.mine.kino.utils;

import static nu.mine.kino.Constants.*;
import static nu.mine.kino.utils.JSONUtils.*;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.StatusType;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;

/**
 * @author Masatomi KINO
 * @version $Revision$
 */
/**
 * @author Masatomi KINO
 * @version $Revision$
 */
@Slf4j
public class Utils {
    public static String getRandomString() {
        return RandomStringUtils.randomAlphanumeric(50);
    }

    /**
     * Requestから リクエストURLを取得する。 AWSなどでロードバランサが SSLをほどいて
     * HTTPへ転送する場合に、request.getRequestURL がHTTPになってしまうことがあり
     * その対応として、ロードバランサ経由の場合は、"X-Forwarded-Proto"
     * ヘッダにもとのプロトコルが入っているので、ソレで置換する対応を入れた。
     * 
     * http://d.hatena.ne.jp/kusakari/20090202/1233564289
     * 
     * 
     * @param request
     * @return
     */
    public static String getRequestURL(HttpServletRequest request) {

        log.debug("--------------");
        StringBuffer sb = new StringBuffer();
        Enumeration<String> headernames = request.getHeaderNames();
        while (headernames.hasMoreElements()) {
            String name = (String) headernames.nextElement();
            Enumeration<String> headervals = request.getHeaders(name);
            while (headervals.hasMoreElements()) {
                String val = (String) headervals.nextElement();
                sb.append(name);
                sb.append(":");
                sb.append(val);
                sb.append("\n");
            }
        }
        log.debug(new String(sb));
        log.debug("--------------");

        String redirect_url = new String(request.getRequestURL());
        if (request.getHeader("X-Forwarded-Proto") != null) {
            if (redirect_url.startsWith("http://")) {
                redirect_url = redirect_url.replaceFirst("http://",
                        request.getHeader("X-Forwarded-Proto") + "://");
            } else {
                redirect_url = redirect_url.replaceFirst("https://",
                        request.getHeader("X-Forwarded-Proto") + "://");
            }
        }
        return redirect_url;
    }

    public static String decodeBase64String(String base64Data) {
        return new String(Base64.decodeBase64(base64Data));
    }

    public static byte[] decodeBase64(String base64String) {
        return Base64.decodeBase64(base64String);
    }

    public static String encodeBase64URLSafeString(byte[] binaryData) {
        return Base64.encodeBase64URLSafeString(binaryData);
    }

    public static String sha256(String target) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(target.getBytes());
            return Utils.encodeBase64URLSafeString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * CSRF対策。 セッションが存在するか、存在するなら、セッション内のstate 属性とリクエストパラメタのstateパラメタの値の一致チェック
     * 
     * @param request
     * @throws ServletException
     */
    public static void checkCSRF(HttpServletRequest request)
            throws ServletException {
        HttpSession session = request.getSession(false);
        if (session == null) {
            throw new ServletException("Bad Request(session is null.)");
        }

        log.debug("Redirect後のsession id: {}", session.getId());
        String requestState = request.getParameter(PARAM_STATE);
        String sessionState = (String) session.getAttribute(SESSION_STATE);
        log.debug("requestState:[{}]", requestState);
        log.debug("sessionState:[{}]", sessionState);
        if (!requestState.equals(sessionState)) {
            throw new ServletException("前回のリクエストと今回のstate値が一致しないため、エラー。");
        }
    }

    /**
     * レスポンスのHTTP Response Statusのチェック。400番台、500番台の場合例外
     * 
     * @param restResponse
     * @throws ServletException
     */
    public static void checkAccessTokenResult(Response restResponse)
            throws ServletException {
        StatusType statusInfo = restResponse.getStatusInfo();
        switch (statusInfo.getFamily()) {
        case CLIENT_ERROR:
        case SERVER_ERROR:
            String message = String.format("Status: %s:[%s]",
                    statusInfo.getStatusCode(), statusInfo.getReasonPhrase());
            log.error("{}", restResponse.getStatusInfo());
            throw new ServletException(message);
        default:
            break;
        }
    }

    /**
     * AccessToken取得のためのMapを作成する。Qiitaだけ、
     * 
     * <pre>
     * Content-Type: application/x-www-form-urlencoded
     * </pre>
     * 
     * を受け付けないので、パラメタ生成の処理を分けている。
     * 
     * @param redirect_url
     * @param client_id
     * @param client_secret
     * @param authorizationCode
     * @param client
     * @param mediaType
     * @return
     */
    private static Map<String, ?> createMap(String redirect_url,
            String client_id, String client_secret, String authorizationCode,
            Client client, MediaType mediaType) {

        String grant_type = "authorization_code";
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<String, String>();
        formParams.putSingle("redirect_uri", redirect_url);
        formParams.putSingle("grant_type", grant_type);
        formParams.putSingle("client_id", client_id);
        formParams.putSingle("client_secret", client_secret);
        formParams.putSingle("code", authorizationCode);

        if (mediaType.equals(MediaType.APPLICATION_JSON_TYPE)) {
            Map<String, String> jsonParams = new HashMap<String, String>();
            jsonParams.put("redirect_uri", redirect_url);
            jsonParams.put("grant_type", grant_type);
            jsonParams.put("client_id", client_id);
            jsonParams.put("client_secret", client_secret);
            jsonParams.put("code", authorizationCode);
            return jsonParams;
        }
        return formParams;

    }

    public static String getAccessTokenJSONForPKCE(String oauth_server,
            String redirect_url, String client_id, String client_secret,
            String authorizationCode, String code_verifier, Client client)
            throws ServletException {
        return getAccessTokenJSONForPKCE(oauth_server, redirect_url, client_id,
                client_secret, authorizationCode, code_verifier, client,
                MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    public static String getAccessTokenJSONForPKCE(String oauth_server,
            String redirect_url, String client_id, String client_secret,
            String authorizationCode, String code_verifier, Client client,
            MediaType mediaType) throws ServletException {
        String result = null;

        Map<String, String> formParams = (Map<String, String>) createMapForPKCE(
                redirect_url, client_id, client_secret, authorizationCode,
                code_verifier, client, mediaType);

        log.debug("OAuthServer:{}", oauth_server);
        log.debug("MediaType: {}", mediaType);
        Response restResponse = client //
                .target(oauth_server) //
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.entity(formParams, mediaType));
        result = restResponse.readEntity(String.class);
        log.debug("result: {}", result);
        checkAccessTokenResult(restResponse);

        return result;
    }

    /**
     * AccessToken取得のためのMapを作成する。Qiitaだけ、
     * 
     * <pre>
     * Content-Type: application/x-www-form-urlencoded
     * </pre>
     * 
     * を受け付けないので、パラメタ生成の処理を分けている。
     * 
     * @param redirect_url
     * @param client_id
     * @param client_secret
     * @param authorizationCode
     * @param client
     * @param mediaType
     * @return
     */
    private static Map<String, ?> createMapForPKCE(String redirect_url,
            String client_id, String client_secret, String authorizationCode,
            String code_verifier, Client client, MediaType mediaType) {

        String grant_type = "authorization_code";
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<String, String>();
        formParams.putSingle("redirect_uri", redirect_url);
        formParams.putSingle("grant_type", grant_type);
        formParams.putSingle("client_id", client_id);
//        formParams.putSingle("client_secret", client_secret);
        formParams.putSingle("code", authorizationCode);
        formParams.putSingle("code_verifier", code_verifier);

        if (mediaType.equals(MediaType.APPLICATION_JSON_TYPE)) {
            Map<String, String> jsonParams = new HashMap<String, String>();
            jsonParams.put("redirect_uri", redirect_url);
            jsonParams.put("grant_type", grant_type);
            jsonParams.put("client_id", client_id);
//            jsonParams.put("client_secret", client_secret);
            jsonParams.put("code", authorizationCode);
            jsonParams.put("code_verifier", code_verifier);
            return jsonParams;
        }
        return formParams;

    }

    public static String getAccessTokenJSON(String oauth_server,
            String redirect_url, String client_id, String client_secret,
            String authorizationCode, Client client, MediaType mediaType)
            throws ServletException {
        String result = null;

        Map<String, String> formParams = (Map<String, String>) createMap(
                redirect_url, client_id, client_secret, authorizationCode,
                client, mediaType);

        log.debug("OAuthServer:{}", oauth_server);
        log.debug("MediaType: {}", mediaType);
        Response restResponse = client //
                .target(oauth_server) //
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.entity(formParams, mediaType));
        result = restResponse.readEntity(String.class);
        log.debug("result: {}", result);
        checkAccessTokenResult(restResponse);

        return result;

    }

    public static String getAccessTokenJSON(String oauth_server,
            String redirect_url, String client_id, String client_secret,
            String authorizationCode, Client client) throws ServletException {
        return getAccessTokenJSON(oauth_server, redirect_url, client_id,
                client_secret, authorizationCode, client,
                MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    public static String getAccessTokenJSON(String oauth_server,
            String redirect_url, String client_id, String client_secret,
            String authorizationCode) throws ServletException {
        Client client = ClientBuilder.newClient();
        return getAccessTokenJSON(oauth_server, redirect_url, client_id,
                client_secret, authorizationCode, client);
    }

    public static String getResource(String target, String accessToken,
            Client client) {
        Response restResponse = client.target(target)
                .queryParam("schema", "openid")//
                .request(MediaType.APPLICATION_JSON_TYPE)
                .header("Authorization", "Bearer " + accessToken).get();

        String result = restResponse.readEntity(String.class);
        log.debug(result);
        return result;
    }

    public static String getResource(String resource_server,
            String accessToken) {

        Client client = ClientBuilder.newClient();
        return getResource(resource_server, accessToken, client);

    }

    /**
     * プロクシ経由でSSLを通れるように対応したClient。
     * 
     * @param properties
     * @return
     */
    public static Client createSecureClient(String... properties) {

        ClientConfig config = new ClientConfig();
        config.connectorProvider(new ApacheConnectorProvider());
        if (ArrayUtils.isNotEmpty(properties)) {
            // providerをproxy対応?にする
            String proxyHost = properties[0];
            config.property(ClientProperties.PROXY_URI, proxyHost);
            if (properties.length > 2) {
                String userName = properties[1];
                String password = properties[2];
                config.property(ClientProperties.PROXY_USERNAME, userName);
                config.property(ClientProperties.PROXY_PASSWORD, password);
            }
        }

        SSLContext sslContext = createSSLContext();
        HostnameVerifier hostnameVerifier = createHostNameVerifier();

        // builderの生成
        ClientBuilder b = ClientBuilder.newBuilder().withConfig(config)
                .sslContext(sslContext).hostnameVerifier(hostnameVerifier);
        return b.build();
    }

    private static SSLContext createSSLContext() {
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null,
                    new X509TrustManager[] { new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain,
                                String authType) throws CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain,
                                String authType) throws CertificateException {
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    } }, new SecureRandom());
            // HttpsURLConnection
            // .setDefaultSSLSocketFactory(sslContext.getSocketFactory());

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        return sslContext;
    }

    private static HostnameVerifier createHostNameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
    }

    public static boolean checkHSSignature(SignedJWT decodeObject,
            byte[] sharedSecret) throws JOSEException {
        JWSVerifier verifier = new MACVerifier(sharedSecret);
        boolean verify = decodeObject.verify(verifier);
        log.debug("valid？: {}", verify);
        return verify;
    }

    public static boolean checkRSSignature(SignedJWT decodeObject,
            String jwks_uri) throws JOSEException, IOException, ParseException {
        // Headerから KeyIDを取得して、
        String keyID = decodeObject.getHeader().getKeyID();
        log.debug("KeyID: {}", keyID);

        // ちなみにGoogleは
        // http://qiita.com/trysmr/items/e8d4225ff6a603e9e21a によると
        // https://www.googleapis.com/oauth2/v3/certs
        // ちなみにAuthleteは
        // https://[サーバ名]/api/jwks
        // だがデフォルトだとかえんないっぽい。設定しないとかな。
        RSAKey rsaKey = getRSAKey(jwks_uri, keyID);
        JWSVerifier verifier = new RSASSAVerifier(rsaKey);
        boolean verify = decodeObject.verify(verifier);
        log.debug("valid？: {}", verify);
        return verify;
    }

    // public static boolean checkRSSignature(SignedJWT decodeObject,
    // byte[] publicKey) {
    //
    // }

    public static boolean checkIdToken(String id_token, String jwks_uri,
            String secret) throws ServletException {
        // ココ手動でクチャクチャやってるけど、Nimbusを使って書き換え。
        // String[] id_token_parts = id_token.split("\\.");
        //
        // String ID_TOKEN_HEADER = base64DecodeStr(id_token_parts[0]);
        // String ID_TOKEN_PAYLOAD = base64DecodeStr(id_token_parts[1]);
        // // String ID_TOKEN_SIGNATURE =
        // // base64DecodeStr(id_token_parts[2]);
        // log.debug("ID_TOKEN_HEADER: {}", ID_TOKEN_HEADER);
        // log.debug("ID_TOKEN_PAYLOAD: {}", ID_TOKEN_PAYLOAD);
        // // log.debug("ID_TOKEN_SIGNATURE: {}", ID_TOKEN_SIGNATURE);

        try {
            // JWTの仕様に基づいて、デコードしてみる。
            SignedJWT decodeObject = SignedJWT.parse(id_token);
            log.debug("Header : " + decodeObject.getHeader());
            log.debug("Payload: " + decodeObject.getPayload());
            log.debug("Sign   : " + decodeObject.getSignature());

            JWSAlgorithm algorithm = decodeObject.getHeader().getAlgorithm();
            JWTClaimsSet set = decodeObject.getJWTClaimsSet();
            log.debug("Algorithm: {}", algorithm.getName());
            log.debug("Subject: {}", set.getSubject());
            log.debug("Issuer: {}", set.getIssuer());
            log.debug("Audience: {}", set.getAudience());
            log.debug("Nonce: {}", set.getClaim("nonce"));
            log.debug("now before ExpirationTime?: {}",
                    new Date().before(set.getExpirationTime()));

            if (algorithm.getName().startsWith("HS")) {
                log.debug("共通鍵({})", algorithm.getName());
                byte[] sharedSecret = secret.getBytes(); // バイト列に変換
                return checkHSSignature(decodeObject, sharedSecret);
            } else {
                log.debug("公開鍵({})", algorithm.getName());
                return checkRSSignature(decodeObject, jwks_uri);
            }

        } catch (ParseException e) {
            log.warn("サーバの公開鍵の取得に失敗しています.{}", e.getMessage());
        } catch (IOException e) {
            log.warn("サーバの公開鍵の取得に失敗しています.{}", e.getMessage());
        } catch (JOSEException e) {
            log.warn("Verify処理に失敗しています。{}", e.getMessage());
        }
        return false;

        // ホントはPAYLOADの nonce値とSessionのnonce値の一致チェックが必要。まだやってない。
        // // https://developer.yahoo.co.jp/yconnect/v2/hybrid/jwks.html
        // // JWK のエンドポイントから、公開鍵を取得する。
        // // もしくは Public Keys エンドポイント
        // // https://developer.yahoo.co.jp/yconnect/v2/hybrid/public_keys.html
        // String jwkEndpoint =
        // "https://auth.login.yahoo.co.jp/yconnect/v2/jwks";

    }

}
