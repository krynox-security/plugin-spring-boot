package net.krynox.captcha.spring;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the Krynox Captcha starter, bound from the {@code krynox.*} namespace
 * (e.g. {@code application.yml}):
 *
 * <pre>{@code
 * krynox:
 *   secret: ${KRYNOX_SECRET_KEY}
 *   paths: [/signup, /contact]
 * }</pre>
 */
@ConfigurationProperties("krynox")
public class KrynoxProperties {

  /** Master switch for the auto-configured verify filter. */
  private boolean enabled = true;

  /** Secret key (kcps_…). Required for the filter to activate. */
  private String secret;

  /** Data-plane host. */
  private String apiHost = "https://api.krynox.net";

  /**
   * URL patterns (servlet-style, e.g. {@code /signup}, {@code /api/*}) to protect. The filter is
   * only registered when at least one path is set — nothing is enforced until you opt endpoints in.
   */
  private List<String> paths = List.of();

  /** HTTP methods to enforce on. */
  private List<String> methods = List.of("POST", "PUT", "PATCH", "DELETE");

  /** Request parameter (form field) carrying the solved token. */
  private String field = "krynox-captcha";

  /** Request parameter carrying the honeypot decoy value (injected by the widget as {@code krynox-hp}). */
  private String honeypotField = "krynox-hp";

  /** Header checked when the parameter is absent — for fetch/API clients. */
  private String header = "X-Krynox-Captcha";

  /** Per-attempt request timeout, in milliseconds. */
  private long timeoutMs = 5000;

  /** Transient-failure (network / 429 / 5xx) retries. */
  private int retries = 2;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String getSecret() {
    return secret;
  }

  public void setSecret(String secret) {
    this.secret = secret;
  }

  public String getApiHost() {
    return apiHost;
  }

  public void setApiHost(String apiHost) {
    this.apiHost = apiHost;
  }

  public List<String> getPaths() {
    return paths;
  }

  public void setPaths(List<String> paths) {
    this.paths = paths;
  }

  public List<String> getMethods() {
    return methods;
  }

  public void setMethods(List<String> methods) {
    this.methods = methods;
  }

  public String getField() {
    return field;
  }

  public void setField(String field) {
    this.field = field;
  }

  public String getHoneypotField() {
    return honeypotField;
  }

  public void setHoneypotField(String honeypotField) {
    this.honeypotField = honeypotField;
  }

  public String getHeader() {
    return header;
  }

  public void setHeader(String header) {
    this.header = header;
  }

  public long getTimeoutMs() {
    return timeoutMs;
  }

  public void setTimeoutMs(long timeoutMs) {
    this.timeoutMs = timeoutMs;
  }

  public int getRetries() {
    return retries;
  }

  public void setRetries(int retries) {
    this.retries = retries;
  }
}
