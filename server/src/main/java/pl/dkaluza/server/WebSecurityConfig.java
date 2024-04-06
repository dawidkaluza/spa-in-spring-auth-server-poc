package pl.dkaluza.server;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Configuration
@EnableWebSecurity
class WebSecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, ExtendedRedirectStrategy extendedRedirectStrategy) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .authorizationEndpoint(authorization ->
                authorization
                    .authorizationResponseHandler((req, res, auth) -> {
                        var authorizationCodeRequestAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) auth;
                        var uriBuilder = UriComponentsBuilder
                            .fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
                            .queryParam(OAuth2ParameterNames.CODE, authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());

                        if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
                            uriBuilder.queryParam(
                                OAuth2ParameterNames.STATE,
                                UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
                        }

                        var redirectUri = uriBuilder.build(true).toUriString();
                        extendedRedirectStrategy.sendRedirect(req, res, redirectUri);
                    })
                    .errorResponseHandler((req, res, exception) -> {
                        var authorizationCodeRequestAuthenticationException = (OAuth2AuthorizationCodeRequestAuthenticationException) exception;
                        var error = authorizationCodeRequestAuthenticationException.getError();
                        var authorizationCodeRequestAuthentication = authorizationCodeRequestAuthenticationException.getAuthorizationCodeRequestAuthentication();

                        if (authorizationCodeRequestAuthentication == null ||
                            !StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
                            res.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
                            return;
                        }

                        var uriBuilder = UriComponentsBuilder
                            .fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
                            .queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());

                        if (StringUtils.hasText(error.getDescription())) {
                            uriBuilder.queryParam(
                                OAuth2ParameterNames.ERROR_DESCRIPTION,
                                UriUtils.encode(error.getDescription(), StandardCharsets.UTF_8));
                        }
                        if (StringUtils.hasText(error.getUri())) {
                            uriBuilder.queryParam(
                                OAuth2ParameterNames.ERROR_URI,
                                UriUtils.encode(error.getUri(), StandardCharsets.UTF_8));
                        }
                        if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
                            uriBuilder.queryParam(
                                OAuth2ParameterNames.STATE,
                                UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
                        }

                        var redirectUri = uriBuilder.build(true).toUriString();
                        extendedRedirectStrategy.sendRedirect(req, res, redirectUri);
                    })
                    .consentPage("/consent-page")
            )
            .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
            .cors(Customizer.withDefaults())
            // Redirect to the login page when not authenticated from the
            // authorization endpoint
            .exceptionHandling(handler -> handler
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("http://localhost:9090/sign-in"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            )
            // Accept access tokens for User Info and/or Client Registration
            .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }


    @Bean
    @Order(2)
    public SecurityFilterChain userAuthSecurityFilterChain(HttpSecurity http, RestfulRedirectStrategy redirectStrategy) throws Exception {
        //noinspection Convert2MethodRef
        http
            .securityMatcher("/sign-in", "/sign-out")
            .cors(Customizer.withDefaults())
            .csrf((csrf) -> csrf.disable())
            .formLogin(form -> form
                .loginPage("http://localhost:9090/sign-in")
                .loginProcessingUrl("/sign-in")
                .successHandler((req, res, auth) -> {
                    var savedReq = new HttpSessionRequestCache().getRequest(req, res);
                    redirectStrategy.sendRedirect(req, res, savedReq == null ? "" : savedReq.getRedirectUrl());
                })
                .failureHandler((req, res, ex) ->
                    res.sendError(HttpServletResponse.SC_UNAUTHORIZED)
                )
            )
            .logout(logout -> logout
                .logoutUrl("/sign-out")
                .logoutSuccessUrl("http://localhost:9090/sign-in?sign-out")
            )
            .exceptionHandling(handler -> handler
                .authenticationEntryPoint(
                    new HttpStatusEntryPoint(HttpStatus.FORBIDDEN)
                )
                .accessDeniedHandler((req, res, ex) -> {
                    logger.debug("Access denied handler caught exception", ex);
                    res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                })
            )
            .authorizeHttpRequests(authorize ->
                authorize
                    .anyRequest().authenticated()
            );

        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        //noinspection Convert2MethodRef
        http
            .cors(Customizer.withDefaults())
            .csrf(csrf -> csrf.disable());

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.addAllowedOrigin("http://localhost:9090/");
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    InMemoryUserDetailsManager userDetailsService(PasswordEncoder passwordEncoder) {
        return new InMemoryUserDetailsManager(
            User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin"))
                .build()
        );
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient webappClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://client/authorize")
            .scope("openid").scope("profile")
            .clientSettings(
                ClientSettings.builder()
                    .requireProofKey(true)
                    .requireAuthorizationConsent(true)
                    .build()
            )
            .build();

        return new InMemoryRegisteredClientRepository(webappClient);
    }
}
