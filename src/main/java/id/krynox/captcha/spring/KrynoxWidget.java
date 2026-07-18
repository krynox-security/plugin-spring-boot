package id.krynox.captcha.spring;

/**
 * Server-rendered widget embed helper — returns an HTML string you can drop into a Thymeleaf/JSP
 * template or a controller response. In Thymeleaf:
 *
 * <pre>{@code
 * <div th:utext="${T(id.krynox.captcha.spring.KrynoxWidget).tag('kcpt_your_site_key')}"></div>
 * }</pre>
 */
public final class KrynoxWidget {

  private static final String DEFAULT_API = "https://api.krynox.net";
  private static final String DEFAULT_CDN = "https://cdn.krynox.net";

  private KrynoxWidget() {}

  /** The loader {@code <script>} + {@code <krynox-captcha>} element for the given site key. */
  public static String tag(String sitekey) {
    return tag(sitekey, DEFAULT_API, DEFAULT_CDN);
  }

  /** As {@link #tag(String)}, with explicit data-plane and CDN hosts (self-hosting). */
  public static String tag(String sitekey, String apiHost, String cdnHost) {
    String api = trim(apiHost) ;
    String challenge = api + "/challenge?sitekey=" + urlEncode(sitekey == null ? "" : sitekey);
    return script(cdnHost) + "<krynox-captcha challenge=\"" + esc(challenge) + "\"></krynox-captcha>";
  }

  /** Just the loader {@code <script>} tag. */
  public static String script(String cdnHost) {
    String src = trim(cdnHost) + "/widget/krynox-captcha.js";
    return "<script src=\"" + esc(src) + "\" type=\"module\" async defer></script>";
  }

  private static String trim(String host) {
    return (host == null ? DEFAULT_CDN : host).replaceAll("/+$", "");
  }

  private static String urlEncode(String s) {
    return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
  }

  private static String esc(String s) {
    return s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;");
  }
}
