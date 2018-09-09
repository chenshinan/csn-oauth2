package com.chenshinan.security.oauth2.controller;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author shinan.chen
 * @date 2018/9/9
 */
@RestController
public class TestEndPoint {

    /**
     * 下单，需要授权认证
     * @param id
     * @return
     */
    @GetMapping("/order/{id}")
    public String getOrder(@PathVariable Long id){
        return "order id = "+id;
    }

    /**
     * 访问商品，不需要认证
     * @param id
     * @return
     */
    @GetMapping("/product/{id}")
    public String getProduct(@PathVariable Long id){

        return "product id = "+id;
    }
}
