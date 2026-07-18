package id.krynox.captcha.spring;

import jakarta.servlet.Filter;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for Krynox Captcha. Activates when a {@code krynox.secret} is present. The
 * verify {@link KrynoxFilter} is only registered when {@code krynox.paths} names at least one URL
 * pattern, so nothing is enforced until you opt endpoints in.
 */
@AutoConfiguration
@ConditionalOnClass(Filter.class)
@ConditionalOnProperty(prefix = "krynox", name = "secret")
@EnableConfigurationProperties(KrynoxProperties.class)
public class KrynoxAutoConfiguration {

  private static final Logger log = System.getLogger(KrynoxAutoConfiguration.class.getName());

  @Bean
  @ConditionalOnMissingBean
  public KrynoxVerifier krynoxVerifier(KrynoxProperties props) {
    return new KrynoxVerifier(props);
  }

  @Bean
  public FilterRegistrationBean<KrynoxFilter> krynoxFilterRegistration(
      KrynoxVerifier verifier, KrynoxProperties props) {

    FilterRegistrationBean<KrynoxFilter> reg = new FilterRegistrationBean<>();
    reg.setFilter(new KrynoxFilter(verifier, props));
    reg.setName("krynoxCaptchaFilter");

    if (!props.isEnabled() || props.getPaths().isEmpty()) {
      // Register but map nothing — the filter stays inert until krynox.paths is configured.
      reg.setEnabled(false);
      log.log(Level.INFO, "Krynox Captcha filter is inert (set krynox.paths to protect endpoints).");
    } else {
      reg.setUrlPatterns(props.getPaths());
      log.log(Level.INFO, "Krynox Captcha filter enforcing on " + props.getMethods() + " for " + props.getPaths());
    }
    return reg;
  }
}
