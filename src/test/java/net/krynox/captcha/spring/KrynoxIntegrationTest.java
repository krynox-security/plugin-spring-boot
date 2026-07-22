package net.krynox.captcha.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

/**
 * Drives the auto-configured {@link KrynoxFilter} over real HTTP (embedded Tomcat) against a
 * self-contained in-JVM mock data plane. Asserts the full contract: pass/reject, reasons/agent/human
 * surfaced on the request attribute, header fallback, non-protected passthrough, 503→200 retry.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = KrynoxIntegrationTest.TestApp.class,
    properties = {"krynox.secret=kcps_test", "krynox.paths=/submit"})
class KrynoxIntegrationTest {

  private static HttpServer mock;
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final ConcurrentHashMap<String, Integer> RETRIES = new ConcurrentHashMap<>();
  static volatile String lastHoneypot = "__unset__";

  @BeforeAll
  static void startMock() throws IOException {
    mock = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    mock.createContext("/siteverify", exchange -> {
      byte[] in = exchange.getRequestBody().readAllBytes();
      JsonNode body = MAPPER.readTree(in.length == 0 ? "{}" : new String(in, StandardCharsets.UTF_8));
      String token = body.path("response").asText("");
      String key = body.path("idempotency_key").asText("nokey");
      lastHoneypot = body.has("honeypot") ? body.path("honeypot").asText("") : "__absent__";

      String json;
      int status = 200;
      if ("RETRY".equals(token) && RETRIES.merge(key, 1, Integer::sum) == 1) {
        status = 503;
        json = "upstream";
      } else if (token.isEmpty() || "BAD".equals(token)) {
        json = "{\"success\":false,\"error-codes\":[\"invalid-input-response\"],\"reasons\":[]}";
      } else if (!"__absent__".equals(lastHoneypot) && !lastHoneypot.isEmpty()) {
        json = "{\"success\":false,\"error-codes\":[\"honeypot-tripped\"],\"reasons\":[\"honeypot-tripped\"]}";
      } else {
        json =
            "{\"success\":true,\"score\":0.95,\"risk\":\"low\",\"hostname\":\"example.com\","
                + "\"challenge_ts\":\"2026-01-01T00:00:00Z\",\"error-codes\":[],"
                + "\"reasons\":[\"tor-exit\",\"elevated-request-rate\"],"
                + "\"agent\":{\"verified\":true,\"name\":\"agent.openai.com\",\"allowlisted\":true},"
                + "\"human\":{\"attested\":true,\"method\":\"private-access-token\",\"issuer\":\"demo-pat.issuer.cloudflare.com\"}}";
      }
      byte[] out = json.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(status, out.length);
      exchange.getResponseBody().write(out);
      exchange.close();
    });
    mock.start();
  }

  @AfterAll
  static void stopMock() {
    if (mock != null) mock.stop(0);
  }

  @DynamicPropertySource
  static void apiHost(DynamicPropertyRegistry registry) {
    registry.add("krynox.api-host", () -> "http://127.0.0.1:" + mock.getAddress().getPort());
  }

  @LocalServerPort int port;

  private final TestRestTemplate rest = new TestRestTemplate();

  private String url(String path) {
    return "http://localhost:" + port + path;
  }

  private ResponseEntity<String> postForm(String path, String token) {
    return postForm(path, token, null);
  }

  private ResponseEntity<String> postForm(String path, String token, String honeypot) {
    HttpHeaders h = new HttpHeaders();
    h.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    if (token != null) form.add("krynox-captcha", token);
    if (honeypot != null) form.add("krynox-hp", honeypot);
    return rest.postForEntity(url(path), new HttpEntity<>(form, h), String.class);
  }

  @Test
  void goodTokenPassesAndSurfacesResult() {
    ResponseEntity<String> res = postForm("/submit", "goodtoken");
    assertThat(res.getStatusCode().value()).isEqualTo(200);
    assertThat(res.getBody()).contains("tor-exit");
    assertThat(res.getBody()).contains("agent.openai.com");
    assertThat(res.getBody()).contains("attested=true");
    assertThat(res.getBody()).contains("risk=low");
  }

  @Test
  void badTokenRejected() {
    ResponseEntity<String> res = postForm("/submit", "BAD");
    assertThat(res.getStatusCode().value()).isEqualTo(403);
    assertThat(res.getBody()).contains("captcha_failed");
  }

  @Test
  void missingTokenRejected() {
    assertThat(postForm("/submit", null).getStatusCode().value()).isEqualTo(403);
  }

  @Test
  void goodTokenViaHeader() {
    HttpHeaders h = new HttpHeaders();
    h.set("X-Krynox-Captcha", "goodtoken");
    ResponseEntity<String> res =
        rest.exchange(url("/submit"), HttpMethod.POST, new HttpEntity<>(null, h), String.class);
    assertThat(res.getStatusCode().value()).isEqualTo(200);
  }

  @Test
  void unprotectedPathPassesThrough() {
    ResponseEntity<String> res = rest.getForEntity(url("/open"), String.class);
    assertThat(res.getStatusCode().value()).isEqualTo(200);
    assertThat(res.getBody()).isEqualTo("open");
  }

  @Test
  void retryRecovers() {
    assertThat(postForm("/submit", "RETRY").getStatusCode().value()).isEqualTo(200);
  }

  @Test
  void cleanSubmitDoesNotTripHoneypot() {
    lastHoneypot = "__unset__";
    ResponseEntity<String> res = postForm("/submit", "goodtoken");
    assertThat(res.getStatusCode().value()).isEqualTo(200);
    // An empty/absent decoy is never penalised.
    assertThat(lastHoneypot).isIn("__absent__", "");
  }

  @Test
  void filledHoneypotIsForwardedAndRejected() {
    lastHoneypot = "__unset__";
    ResponseEntity<String> res = postForm("/submit", "goodtoken", "bot@spam.com");
    // The krynox-hp field reached /siteverify as `honeypot` …
    assertThat(lastHoneypot).isEqualTo("bot@spam.com");
    // … and the enforce-mode data plane rejected it.
    assertThat(res.getStatusCode().value()).isEqualTo(403);
    assertThat(res.getBody()).contains("captcha_failed");
  }

  @SpringBootApplication
  static class TestApp {
    @Bean
    Controller controller() {
      return new Controller();
    }
  }

  @RestController
  static class Controller {
    @PostMapping("/submit")
    String submit(@RequestAttribute("krynox") KrynoxResult k) {
      return "ok reasons=" + k.reasons() + " agentName=" + (k.agent() == null ? "-" : k.agent().name())
          + " attested=" + (k.human() != null && k.human().attested()) + " risk=" + k.risk();
    }

    @GetMapping("/open")
    String open() {
      return "open";
    }
  }
}
