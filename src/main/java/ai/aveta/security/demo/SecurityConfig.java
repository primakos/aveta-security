package ai.aveta.security.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.boot.autoconfigure.security.SecurityProperties;

import com.fasterxml.jackson.databind.ObjectMapper;

@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	  private SecurityProperties securityProperties;
	  
	@Autowired
	public void configureglobal(AuthenticationManagerBuilder auth) throws Exception{
		auth.inMemoryAuthentication().withUser("Username")
		    .password(passwordEncoder().encode("password")).roles("USER");
		
		
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	}
	
	@Bean 
	 public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    http.cors()
	    .and()
        .headers()
        .frameOptions()
        .disable()
        .and()
        .csrf()
        .disable()
        .authorizeHttpRequests()
        .antMatchers(securityProperties.getApiMatcher())
        .authenticated();
	    return http.build();
	}

	@Bean
	  public CorsConfigurationSource corsConfigurationSource() {
	    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	    if (null != securityProperties.getCorsConfiguration()) {
	      source.registerCorsConfiguration("/**", securityProperties.getCorsConfiguration());
	    }
	    return source;
	  }
	
	 @Bean
	  public JwtAccessTokenCustomizer jwtAccessTokenCustomizer(ObjectMapper mapper) {
	    return new JwtAccessTokenCustomizer(mapper);
	  }
	 

	  @Bean
	  public OAuth2RestTemplate oauth2RestTemplate(OAuth2ProtectedResourceDetails details) {
	    OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(details);

	    //Prepare by getting access token once
	    oAuth2RestTemplate.getAccessToken();
	    return oAuth2RestTemplate;
	  }
}
