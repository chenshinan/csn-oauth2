## oauth2

* 通过注入接口的方式，可以通过注入List，可以直接注入所有实现类（适用于适配器模式）

```java
private Iservice sers = Collections.emptyList()
@Autowired
private void setIusb(List<Iusb> lists){
    this.lists =lists;
};
```

### @EnableResourceServer：启用资源服务配置

ResourceServerConfiguration：资源服务配置，通过适配器的方式添加额外配置（资源安全配置 和 http安全配置），`这些配置会在原ResourceServerConfiguration配置类中全部遍历加载进去`

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

* 通过OAuth2AuthenticationManager认证token

OAuth2AuthenticationManager.authenticate方法，调用了ResourceServerSecurityConfigurer中的tokenService来通过token获取认证信息

        tokenService分为两类接口：
        ResourceServerTokenServices：根据accessToken加载客户端信息、根据accessToken获取完整的访问令牌详细信息
        AuthorizationServerTokenServices：创建token、刷新token、获取token

* 将身份信息绑定到SecurityContextHolder中（context上下文中）

#### HttpSecurity（http安全配置）：

配置有哪些路径的请求需要认证