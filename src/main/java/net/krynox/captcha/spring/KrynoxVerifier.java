package net.krynox.captcha.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Verifies solved Krynox tokens against {@code POST /siteverify}. Retries transient failures
 * (network / 429 / 5xx) with a per-verify idempotency key so a retried single-use token replays the
 * first outcome instead of failing.
 */
public class KrynoxVerifier {

  private final KrynoxProperties props;
  private final HttpClient client;
  private final ObjectMapper mapper = new ObjectMapper();

  public KrynoxVerifier(KrynoxProperties props) {
    this.props = props;
    this.client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(props.getTimeoutMs())).build();
  }

  /** Verify {@code token}; {@code remoteip} is optional (may be null). */
  public KrynoxResult verify(String token, String remoteip) {
    if (token == null || token.isEmpty()) {
      return KrynoxResult.failed("missing-input-response");
    }
    ObjectNode body = mapper.createObjectNode();
    body.put("secret", props.getSecret());
    body.put("response", token);
    if (remoteip != null) body.put("remoteip", remoteip);
    if (props.getRetries() > 0) body.put("idempotency_key", UUID.randomUUID().toString());

    JsonNode data = post(props.getApiHost().replaceAll("/+$", "") + "/siteverify", body);
    if (data == null) {
      return KrynoxResult.failed("request-failed");
    }
    return new KrynoxResult(
        data.path("success").asBoolean(false),
        data.hasNonNull("score") ? data.get("score").asDouble() : null,
        text(data, "risk"),
        text(data, "hostname"),
        text(data, "challenge_ts"),
        arr(data, "error-codes"),
        arr(data, "reasons"),
        agent(data),
        human(data));
  }

  private JsonNode post(String url, ObjectNode body) {
    HttpRequest req =
        HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofMillis(props.getTimeoutMs()))
            .header("content-type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
            .build();
    int retries = props.getRetries();
    for (int attempt = 0; attempt <= retries; attempt++) {
      try {
        HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
        int status = res.statusCode();
        if ((status == 429 || status >= 500) && attempt < retries) {
          sleep(attempt);
          continue;
        }
        return mapper.readTree(res.body());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return null;
      } catch (Exception e) {
        if (attempt >= retries) return null;
        sleep(attempt);
      }
    }
    return null;
  }

  private static void sleep(int attempt) {
    try {
      Thread.sleep(Math.min(1000L, 100L * (1L << attempt)));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private static String text(JsonNode n, String k) {
    return n.hasNonNull(k) ? n.get(k).asText() : null;
  }

  private static List<String> arr(JsonNode n, String k) {
    if (!n.has(k) || !n.get(k).isArray()) return List.of();
    List<String> out = new ArrayList<>();
    n.get(k).forEach(e -> out.add(e.asText()));
    return out;
  }

  private static KrynoxResult.Agent agent(JsonNode n) {
    JsonNode a = n.get("agent");
    if (a == null || !a.isObject()) return null;
    return new KrynoxResult.Agent(a.path("verified").asBoolean(false), text(a, "name"), a.path("allowlisted").asBoolean(false));
  }

  private static KrynoxResult.Human human(JsonNode n) {
    JsonNode h = n.get("human");
    if (h == null || !h.isObject()) return null;
    return new KrynoxResult.Human(h.path("attested").asBoolean(false), text(h, "method"), text(h, "issuer"));
  }
}
