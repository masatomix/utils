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
import javax.ws.rs.BadRequestException;
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
@Slf4j
public class Utils {
    public static String getRandomString() {
        return RandomStringUtils.randomAlphanumeric(40);
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

    public static String base64DecodeStr(String input) {
        return new String(Base64.decodeBase64(input));
    }

    public static byte[] base64Decode(String input) {
        return Base64.decodeBase64(input);
    }

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

    public static void checkAccessTokenResult(Response restResponse)
            throws ServletException {
        StatusType statusInfo = restResponse.getStatusInfo();
        switch (statusInfo.getFamily()) {
        case CLIENT_ERROR:
        case SERVER_ERROR:
            String message = String.format("Status: %s:[%s]",
                    statusInfo.getStatusCode(), statusInfo.getReasonPhrase());
            throw new ServletException(message);
        default:
            break;
        }
        // if (statusInfo.getStatusCode() != Status.OK.getStatusCode()) {
        // String message = String.format("%s:[%s]",
        // statusInfo.getStatusCode(), statusInfo.getReasonPhrase());
        // throw new ServletException(message);
        // }
    }

    public static String getAccessToken_JSON_APPLICATION_JSON_TYPE(
            String oauth_server, String redirect_url, String client_id,
            String client_secret, String authorizationCode, Client client)
            throws ServletException {
        String result = null;
        String grant_type = "authorization_code";

        Map<String, String> formParams = new HashMap<String, String>();
        formParams.put("client_secret", client_secret);
        formParams.put("client_id", client_id);
        formParams.put("grant_type", grant_type);
        formParams.put("redirect_uri", redirect_url);
        formParams.put("code", authorizationCode);
        log.debug("OAuthServer:{}", oauth_server);
        Response restResponse = client //
                .target(oauth_server) //
                .request(MediaType.APPLICATION_JSON_TYPE).post(Entity
                        .entity(formParams, MediaType.APPLICATION_JSON_TYPE));
        result = restResponse.readEntity(String.class);
        log.debug(result);
        checkAccessTokenResult(restResponse);

        return result;

    }

    public static String getAccessTokenJSON(String oauth_server,
            String redirect_url, String client_id, String client_secret,
            String authorizationCode, Client client, MediaType mediaType)
            throws ServletException {
        String result = null;
        String grant_type = "authorization_code";
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<String, String>();
        formParams.putSingle("client_secret", client_secret);
        formParams.putSingle("client_id", client_id);
        formParams.putSingle("grant_type", grant_type);
        formParams.putSingle("redirect_uri", redirect_url);
        formParams.putSingle("code", authorizationCode);

        // Map<String, String> formParams = new HashMap<String, String>();
        // formParams.put("client_secret", client_secret);
        // formParams.put("client_id", client_id);
        // formParams.put("grant_type", grant_type);
        // formParams.put("redirect_uri", redirect_url);
        // formParams.put("code", authorizationCode);
        log.debug("OAuthServer:{}", oauth_server);
        Response restResponse = client //
                .target(oauth_server) //
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.entity(formParams, mediaType));
        // .post(Entity.entity(formParams,
        // MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        // .post(Entity.entity(formParams,
        // MediaType.APPLICATION_JSON_TYPE));

        result = restResponse.readEntity(String.class);
        log.debug(result);
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

    public static String getResource(String resource_server, String accessToken,
            Client client) {
        // Client client = createClient();

        // MultivaluedHashMap<String, String> formParams = new
        // MultivaluedHashMap<String, String>();
        // Response restResponse = client.target(usersUrl)
        // .request(MediaType.APPLICATION_JSON_TYPE)
        // .header("Authorization", "token " + accessToken)
        // .post(Entity.entity(formParams,
        // MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        //
        // System.out.println(restResponse.readEntity(String.class));

        log.debug("Resource Server:{}", resource_server);
        Response restResponse = client.target(resource_server)
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

    // public static Client createSecureClient() {
    // // String proxyHost = "http://127.0.0.1:8080";
    // ClientConfig config = new ClientConfig();
    //
    // // providerをproxy対応?にする
    // config.connectorProvider(new ApacheConnectorProvider());
    // // config.property(ClientProperties.PROXY_URI, proxyHost);
    // // config.property(ClientProperties.PROXY_USERNAME, "userName");
    // // config.property(ClientProperties.PROXY_PASSWORD, "password");
    //
    // SSLContext sslContext = createSSLContext();
    // HostnameVerifier hostnameVerifier = createHostNameVerifier();
    //
    // // builderの生成
    // ClientBuilder b = ClientBuilder.newBuilder().withConfig(config)
    // .sslContext(sslContext).hostnameVerifier(hostnameVerifier);
    // return b.build();
    // }

    public static SSLContext createSSLContext() {
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

    public static HostnameVerifier createHostNameVerifier() {
        return new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
    }

    public static boolean checkIdToken(String id_token, String jwks_uri,
            String secret) throws ServletException {
        // String[] id_token_parts = id_token.split("\\.");
        //
        // String ID_TOKEN_HEADER = base64DecodeStr(id_token_parts[0]);
        // String ID_TOKEN_PAYLOAD = base64DecodeStr(id_token_parts[1]);
        // // String ID_TOKEN_SIGNATURE =
        // // base64DecodeStr(id_token_parts[2]);
        // log.debug("ID_TOKEN_HEADER: {}", ID_TOKEN_HEADER);
        // log.debug("ID_TOKEN_PAYLOAD: {}", ID_TOKEN_PAYLOAD);
        // // log.debug("ID_TOKEN_SIGNATURE: {}", ID_TOKEN_SIGNATURE);
        boolean verify = false;

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
                JWSVerifier verifier = new MACVerifier(sharedSecret);
                verify = decodeObject.verify(verifier);
                log.debug("valid？: {}", verify);
                return verify;
            } else {
                log.debug("公開鍵({})", algorithm.getName());
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
                verify = decodeObject.verify(verifier);
                log.debug("valid？: {}", verify);
                return verify;
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
