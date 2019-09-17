package com.realspeed.security.jwtsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.realspeed.security.jwtsecurity.security.JwtAuthenticationProvider;
import com.realspeed.security.jwtsecurity.security.JwtAuthenticationTokenFilter;
import com.realspeed.security.jwtsecurity.security.JwtSuccessHandler;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
@Configuration
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {

	 private static final RequestMatcher PROTECTED_URLS = new OrRequestMatcher(
	            new AntPathRequestMatcher("/api/**")
	    );
	AuthenticationProvider provider;

	public JwtSecurityConfig(final JwtAuthenticationProvider authenticationProvider) {
		super();
		this.provider = authenticationProvider;
	}

	@Bean
	public JwtAuthenticationTokenFilter authenticationTokenFilter() throws Exception {
		JwtAuthenticationTokenFilter filter = new JwtAuthenticationTokenFilter(PROTECTED_URLS);
		filter.setAuthenticationManager(authenticationManager());
		filter.setAuthenticationSuccessHandler(new JwtSuccessHandler());
		return filter;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf()
			.disable()
			.formLogin().disable()
			.httpBasic().disable()
			.logout().disable()
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.exceptionHandling()
			.and()
			.authenticationProvider(provider)
			.addFilterBefore(authenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class)
			.authorizeRequests().requestMatchers(PROTECTED_URLS)
			.authenticated()
			.and()
			.headers()
			.cacheControl();
	}

	@Bean
	AuthenticationEntryPoint forbiddenEntryPoint() {
		return new HttpStatusEntryPoint(HttpStatus.FORBIDDEN);
	}
}
