package com.chenshinan.security.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * @author shinan.chen
 * @date 2018/9/9
 */
@Configuration
public class Oauth2Configuration {

    /**
     * 资源服务器：配置访问资源的限制，需要带授权码才能访问
     */
    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
        /**
         * 资源安全配置
         */
        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
            /**
             * ResourceServerSecurityConfigurer中有核心过滤器：OAuth2AuthenticationProcessingFilter
             * 携带access_token进行访问，会进入OAuth2AuthenticationProcessingFilter之中
             *
             * OAuth2保护资源的预先认证过滤器。如果与OAuth2AuthenticationManager（身份管理器：与token认证相关）结合使用，
             * 则会从到来的请求之中提取一个OAuth2 token，之后使用OAuth2Authentication来填充Spring Security上下文。
             *
             * TokenExtractor：它的作用在于分离出请求中包含的token
             */
            System.out.println("——————————————————————ResourceServerSecurityConfigurer");
            resources.resourceId("order").stateless(true);
        }

        /**
         * http安全配置
         */
        @Override
        public void configure(HttpSecurity http) throws Exception {
            System.out.println("——————————————————————HttpSecurity");
            /**
             * 配置order访问控制，必须认证过后才可以访问
             */
            http.authorizeRequests().antMatchers("/order/**").authenticated();
        }
    }

    /**
     * 身份认证服务器：通过认证信息获取token
     */
    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        AuthenticationManager authenticationManager;
        @Autowired
        RedisConnectionFactory redisConnectionFactory;

        /**
         * 配置AuthorizationServer安全认证的相关信息，创建ClientCredentialsTokenEndpointFilter核心过滤器
         *
         * 在请求到达/oauth/token之前经过了ClientCredentialsTokenEndpointFilter这个过滤
         */
        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            System.out.println("——————————————————————AuthorizationServerSecurityConfigurer");
            /**
             * 主要是让/oauth/token支持client_id以及client_secret作登录认证
             */
            security.allowFormAuthenticationForClients();
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            /**
             * 配置OAuth2的客户端相关信息
             */
            System.out.println("——————————————————————ClientDetailsServiceConfigurer");
            String finalSecret = "{bcrypt}"+new BCryptPasswordEncoder().encode("123456");
            //配置两个客户端,一个用于password认证一个用于client认证
            clients.inMemory().withClient("client_1")
                    .resourceIds("order")
                    .authorizedGrantTypes("client_credentials", "refresh_token")
                    .scopes("select")
                    .authorities("client")
                    .secret(finalSecret)
                    .and()
                    .withClient("client_2")
                    .resourceIds("order")
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("select")
                    .authorities("client")
                    .secret(finalSecret);
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            System.out.println("——————————————————————AuthorizationServerEndpointsConfigurer");
            endpoints
                    .tokenStore(new RedisTokenStore(redisConnectionFactory))
                    .authenticationManager(authenticationManager)
                    .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
        }
    }
}
