package net.krynox.captcha.spring;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Verifies a Krynox Captcha token before the request reaches your controller. The token is read
 * from the configured request parameter ({@code krynox-captcha} by default — works for form posts
 * without consuming the body) and falls back to the {@code X-Krynox-Captcha} header for API clients.
 *
 * <p>On success the {@link KrynoxResult} is exposed as the {@code "krynox"} request attribute and
 * the chain continues; on failure it responds {@code 403} with a JSON body.
 */
public class KrynoxFilter extends OncePerRequestFilter {

  /** Request attribute holding the {@link KrynoxResult}. */
  public static final String ATTRIBUTE = "krynox";

  private final KrynoxVerifier verifier;
  private final KrynoxProperties props;
  private final Set<String> methods;

  public KrynoxFilter(KrynoxVerifier verifier, KrynoxProperties props) {
    this.verifier = verifier;
    this.props = props;
    this.methods = new HashSet<>();
    props.getMethods().forEach(m -> methods.add(m.toUpperCase()));
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {

    if (!methods.contains(request.getMethod().toUpperCase())) {
      chain.doFilter(request, response);
      return;
    }

    String token = request.getParameter(props.getField());
    if (token == null || token.isEmpty()) {
      token = request.getHeader(props.getHeader());
    }

    KrynoxResult result =
        verifier.verify(token, clientIp(request), request.getParameter(props.getHoneypotField()));
    request.setAttribute(ATTRIBUTE, result);

    if (!result.success()) {
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      response.setContentType("application/json");
      response.getWriter().write("{\"success\":false,\"error\":\"captcha_failed\",\"error-codes\":" + jsonArray(result.errorCodes()) + "}");
      return;
    }
    chain.doFilter(request, response);
  }

  private String clientIp(HttpServletRequest request) {
    String trustedHeader = props.getTrustedProxyHeader();
    if (trustedHeader != null && !trustedHeader.isBlank()) {
      String forwarded = request.getHeader(trustedHeader);
      if (forwarded != null && !forwarded.isBlank()) {
        return forwarded.split(",")[0].trim();
      }
    }
    // Safe default: the servlet container's resolved peer. Configure Tomcat's
    // RemoteIpValve/forward-headers strategy, or explicitly opt into a header above.
    return request.getRemoteAddr();
  }

  private static String jsonArray(java.util.List<String> items) {
    StringBuilder sb = new StringBuilder("[");
    for (int i = 0; i < items.size(); i++) {
      if (i > 0) sb.append(',');
      sb.append('"').append(items.get(i).replace("\"", "\\\"")).append('"');
    }
    return sb.append(']').toString();
  }
}
