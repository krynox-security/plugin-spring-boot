package net.krynox.captcha.spring;

import java.util.List;

/**
 * Outcome of a Krynox verification. Set as the request attribute {@code "krynox"} by
 * {@link KrynoxFilter}, so downstream controllers can read the risk signal:
 *
 * <pre>{@code
 * KrynoxResult k = (KrynoxResult) request.getAttribute("krynox");
 * if (k != null && ("high".equals(k.risk()) || k.reasons().contains("tor-exit"))) { ... }
 * }</pre>
 */
public record KrynoxResult(
    boolean success,
    Double score,
    String risk,
    String hostname,
    String challengeTs,
    List<String> errorCodes,
    List<String> reasons,
    Agent agent,
    Human human) {

  /** A cryptographically verified AI agent (Web Bot Auth), when forwarded. */
  public record Agent(boolean verified, String name, boolean allowlisted) {}

  /** A device-attested real human (Private Access Token), when forwarded. */
  public record Human(boolean attested, String method, String issuer) {}

  static KrynoxResult failed(String code) {
    return new KrynoxResult(false, null, null, null, null, List.of(code), List.of(), null, null);
  }
}
