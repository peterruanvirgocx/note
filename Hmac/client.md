# HMAC client

```java
import com.alibaba.fastjson.JSONObject;
import okhttp3.RequestBody;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;

@Component
public class YellowCardApiUtil extends BaseApiUtil{
    @Value("${api.key}")
    private String apiKey;

    @Value("${secret.key}")
    private String secretKey;

    private HashMap<String, String> authenticate(String path, String method, JSONObject body) throws Exception {
//        ObjectMapper mapper = new ObjectMapper();
//        String jsonBody = body == null ? null : mapper.writeValueAsString(body);

        String jsonBody = body == null ? null : body.toJSONString();

        String timestamp = generateTimestamp();

        String message = buildMessageToSign(timestamp, path, method, jsonBody);
        String signature = generateSignature(message);

        String authorization = "YcHmacV1 " + apiKey + ":" + signature;

        HashMap<String, String> result = new HashMap<>();
        result.put("X-YC-Timestamp", timestamp);
        result.put("Authorization", authorization);

        return result;
    }

    private String generateTimestamp() {
        Instant currentInstant = Instant.now();
        // Convert it to an ISO 8601 formatted string
        return currentInstant.toString();
    }

    private String hashRequestBody(String body) throws Exception {
        // Create SHA-256 digest
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(body.getBytes(StandardCharsets.UTF_8));

        // Base64-encode the hash
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    private String buildMessageToSign(String timestamp, String path, String method, String requestBody) throws Exception {
        String message = timestamp + path + method;

        if (("POST".equals(method) || "PUT".equals(method)) && StringUtils.hasLength(requestBody)) {
            String bodyHash = hashRequestBody(requestBody);
            message += bodyHash;
        }

        return message;
    }

    private String generateSignature(String message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        mac.init(keySpec);
        byte[] hmac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Base64-encode the hash
        return Base64.getEncoder().encodeToString(hmac);
    }

    public JSONObject sendGetWithAuth(String url, String path) throws Exception {
        HashMap<String, String> auth = authenticate("/business" + path, "GET", null);
        HashMap<String, String> headers = new HashMap<>();
        headers.put("X-YC-Timestamp",auth.get("X-YC-Timestamp") );
        headers.put("Authorization",auth.get("Authorization") );

        return doGet(headers, url);
    }

    public JSONObject sendPostWithAuth(String url, String path, JSONObject data) throws Exception {
        HashMap<String, String> auth = authenticate("/business" + path, "POST", data);

        HashMap<String, String> headers = new HashMap<>();
        headers.put("X-YC-Timestamp",auth.get("X-YC-Timestamp") );
        headers.put("Authorization",auth.get("Authorization") );

        okhttp3.MediaType mediaType = okhttp3.MediaType.parse("application/json");
        RequestBody body = RequestBody.create(mediaType, data.toJSONString());

        return doPost(body, headers, url);
    }
}
```

```java
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.springframework.stereotype.Component;

import java.util.HashMap;

@Component
@Slf4j
public class BaseApiUtil {

    public static JSONObject doPost(RequestBody formBody, HashMap<String, String> headers, String url)
            throws Exception {

        JSONObject jsonObject = new JSONObject();
        try {
            OkHttpClient client = new OkHttpClient().newBuilder().build();
            Request.Builder builder = new Request.Builder()
                    .url(url)
                    .post(formBody);
            headers.forEach((key, value) -> builder.addHeader(key, value));
            Request request = builder.build();

            Response response = client.newCall(request).execute();

            if (response != null) {
                int statusCode = response.code();

                if (statusCode == 500) {
                    log.error("Server error (500) from URL: {}", url);
                    throw new RuntimeException("Server error (500) from URL: {}" + url);
                }

                 if (statusCode == 404) {
                    log.error("Server error (500) from URL: {}", url);
                    throw new RuntimeException("Resource not found (404) from URL: {}" + url);
                }


                String responseBody = response.body().string();
                if (responseBody != null && !responseBody.isEmpty()) {
                    jsonObject = JSONObject.parseObject(responseBody, JSONObject.class);
                }
            }

        } catch (Exception e) {
            log.error("Post method error with: " + e.toString() + ", url: " + url);
        }

        return jsonObject;
    }

    public static JSONObject doGet(HashMap<String, String> headers, String url) throws Exception {
        JSONObject jsonObject = new JSONObject();

        try {
            OkHttpClient client = new OkHttpClient().newBuilder().build();
            Request.Builder builder = new Request.Builder()
                    .url(url)
                    .get();
            headers.forEach((key, value) -> builder.addHeader(key, value));
            Request request = builder.build();

            Response response = client.newCall(request).execute();

            if (response != null) {
                int statusCode = response.code();

                if (statusCode == 500) {
                    log.error("Server error (500) from URL: {}", url);
                    throw new RuntimeException("Server error (500) from URL: {}" + url);
                }

                  if (statusCode == 404) {
                    log.error("Server error (500) from URL: {}", url);
                    throw new RuntimeException("Resource not found (404) from URL: {}" + url);
                }

                String responseBody = response.body().string();
                if (responseBody != null && !responseBody.isEmpty()) {
                    jsonObject = JSONObject.parseObject(responseBody, JSONObject.class);
                }
            }
        } catch (Exception e) {
            log.error("Get method error with: " + e.toString() + ", url: " + url);

        }
        return jsonObject;
    }
}
```
