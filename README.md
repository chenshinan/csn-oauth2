## oauth2

* 通过注入接口的方式，可以通过注入List，可以直接注入所有实现类（适用于适配器模式）

```java
private Iservice sers = Collections.emptyList()
@Autowired
private void setIusb(List<Iusb> lists){
    this.lists =lists;
};
```

### @EnableResourceServer：启用资源服务配置，注入配置：ResourceServerConfiguration

ResourceServerConfiguration：资源服务配置，通过适配器的方式添加额外配置（资源安全配置 和 http安全配置），`这些配置会在注入的配置类ResourceServerConfiguration中全部遍历加载进去`

```java
public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
    resources.resourceId("order").stateless(true);  //资源安全配置的额外配置
    //resourceId；资源id，认证token时会校验资源是否匹配
}

public void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests().antMatchers("/order/**").authenticated();  //http安全配置的额外配置
}
```

#### ResourceServerSecurityConfigurer（资源安全配置类）：

有许多属性配置（ResourceServerTokenServices），配置核心过滤器OAuth2AuthenticationProcessingFilter，携带access_token进行访问会进入过滤器

`OAuth2AuthenticationProcessingFilter.doFilter()，OAuth2保护资源的预先认证过滤器。如果与OAuth2AuthenticationManager结合使用，则会从到来的请求之中提取一个OAuth2 token，之后使用OAuth2Authentication来填充Spring Security上下文`

* 通过TokenExtractor分离出请求中包含的token

* 通过身份认证管理器AuthenticationManager的实现类`OAuth2AuthenticationManager`认证token

OAuth2AuthenticationManager.authenticate方法，调用了ResourceServerSecurityConfigurer中的tokenService来通过token获取认证信息

        tokenService分为两类接口：
        ResourceServerTokenServices：根据accessToken加载客户端信息、根据accessToken获取完整的访问令牌详细信息
        AuthorizationServerTokenServices：创建token、刷新token、获取token

* 将身份信息绑定到SecurityContextHolder中（context上下文中）

#### HttpSecurity（http安全配置）：

配置有哪些路径的请求需要认证

### @EnableAuthorizationServer：启用认证服务配置，注入配置：AuthorizationServerSecurityConfiguration

AuthorizationServerConfiguration：认证服务配置，通过适配器的方式添加额外配置（），`这些配置会在注入的配置类AuthorizationServerSecurityConfiguration中加载进去`

```java
public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security.allowFormAuthenticationForClients();//主要是让/oauth/token支持client_id以及client_secret作登录认证
}

public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    String finalSecret = "{bcrypt}"+new BCryptPasswordEncoder().encode("123456");
    //配置客户端信息，配置了两个客户端,一个用于password认证一个用于client认证
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

public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    //配置端点相关信息
    endpoints.tokenStore(new RedisTokenStore(redisConnectionFactory))
             .authenticationManager(authenticationManager)
             .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
}
```

#### AuthorizationServerSecurityConfigurer（认证安全配置类）：

配置AuthorizationServer安全认证的相关信息，创建ClientCredentialsTokenEndpointFilter核心过滤器，访问/oauth/token之前会进入过滤器

`ClientCredentialsTokenEndpointFilter.attemptAuthentication()，访问/oauth/token之前会先进入过滤器，分解出client_id和client_secret`

* 从请求中分离出client_id和client_secret

* 通过身份认证管理器AuthenticationManager的实现类`ProviderManager`认证客户端信息

ProviderManager.authenticate()方法，执行了类内部的一系列的AuthenticationProvider对象的authenticate认证方法，而AuthenticationProvider主要实现类是AbstractUserDetailsAuthenticationProvider抽象类的authenticate方法中调用实现类DaoAuthenticationProvider.retrieveUser()，retrieveUser()中调用UserDetailsService.loadUserByUsername()方法加载出用户信息进行认证

* 认证提供类AuthenticationProvider中的`UserDetailsService`接口，用来加载用户信息，提供了几种实现类：InMemoryUserDetailManager`（存储在内存中）`、JdbcUserDetailManager`（存储在数据库）`等

#### ClientDetailsServiceConfigurer（客户端相关信息配置类）：

配置OAuth2的客户端相关信息

#### AuthorizationServerEndpointsConfigurer（端点信息配置类）：

配置AuthorizationServerEndpointsConfigurer端点配置相关类，包括配置身份认证器，配置认证方式，TokenStore，TokenGranter，OAuth2RequestFactory

### Token处理端点TokenEndpoint

经过过滤器的前置校验和身份封装之后，进入/oauth/token端口

* 通过`ClientDetailsService.loadClientByClientId`()加载出客户端信息

* 结合请求信息，创建TokenRequest，将TokenRequest传递给TokenGranter颁发token

* `TokenGranter`颁发token，返回Oauth2AccessToken`（封装了返回token的数据对象）`

TokenGranter的设计思路是使用CompositeTokenGranter管理一个List列表，每一种grantType对应一个具体的真正授权者，在debug过程中可以发现CompositeTokenGranter 内部就是在循环调用五种TokenGranter实现类的grant方法，而granter内部则是通过grantType来区分是否是各自的授权类型

        ResourceOwnerPasswordTokenGranter ==> password密码模式
        AuthorizationCodeTokenGranter ==> authorization_code授权码模式
        ClientCredentialsTokenGranter ==> client_credentials客户端模式
        ImplicitTokenGranter ==> implicit简化模式
        RefreshTokenGranter ==>refresh_token 刷新token专用

* Granter中通过调用`AuthorizationServerTokenServices`的createAccessToken`（创建token）`、refreshAccessToken`（刷新token）`、getAccessToken`（获取token）`

* AuthorizationServerTokenServices中，通过调用`TokenStore`实现对token的操作，调用tokenStore对产生的token和相关信息存储到对应的实现类中，可以是redis，数据库，内存，jwt