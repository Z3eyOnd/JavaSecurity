##  简介

https://zhuanlan.zhihu.com/p/54176956

**Shiro权限管理的过滤器解释**

```
anon:例子/admins/**=anon   #没有参数，表示可以匿名使用。   
authc:例如/admins/user/**=authc   #表示需要认证(登录)才能使用，没有参数   
roles：例子/admins/user/**=roles[admin], #参数可以写多个，多个时必须加上引号，并且参数之间用逗号分割，当有多个参数时，例如admins/user/**=roles["admin,guest"], 每个参数通过才算通过，相当于hasAllRoles()方法。   
perms：例子/admins/user/**=perms[user:add:*], #参数可以写多个，多个时必须加上引号，并且参数之间用逗号分割，例如/admins/user/**=perms["user:add:*,user:modify:*"]，当有多个参数时必须每个参数都通过才通过，想当于isPermitedAll()方法。   
rest：例子/admins/user/**=rest[user], #根据请求的方法，相当于/admins/user/**=perms[user:method] ,其中method为 post，get，delete等。   
port：例子/admins/user/**=port[8081], #当请求的url的端口不是8081是跳转到schemal://serverName:8081?queryString,其中schmal是协议http或https等，serverName是你访问的host,8081是url配置里port的端口，queryString是你访问的url里的？后面的参数。   
authcBasic：例如/admins/user/**=authcBasic #没有参数表示httpBasic认证   
ssl:例子/admins/user/**=ssl #没有参数，表示安全的url请求，协议为https   
user:例如/admins/user/**=user #没有参数表示必须存在用户，当登入操作时不做检查 
```

## demo1

### 环境搭建

```xml
<dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring</artifactId>
</dependency>
```

### 代码

resource/shiro.ini

```ini
[users]
user=user,user
admin=admin,admin

[roles]
admin=*
user=use

```

ShiroTest.java：测试shiro是否可以使用

```java
package com.example.demosec1.demo;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import java.util.Scanner;

public class ShiroTest {
    public static void main(String[] args){
        Scanner sc = new Scanner(System.in);
        System.out.print("Input username:");
        String username = sc.next();
        System.out.print("Input password:");
        String password = sc.next();
        //构建一个SecurityManager环境
        DefaultSecurityManager securityManager = new DefaultSecurityManager();

        // 加载ini，IniRealm读取认证文件，放到SecurityManager中
        IniRealm iniRealm = new IniRealm("classpath:shiro.ini");
        securityManager.setRealm(iniRealm);
        //设置SecurityManager
        SecurityUtils.setSecurityManager(securityManager);

        //获取主体
        Subject subject = SecurityUtils.getSubject();
        //设置token
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        boolean flag;
        //验证
        try {
            subject.login(token);
            flag = true;
        }catch (IncorrectCredentialsException e){
            flag = false;
        }

        System.out.println(flag ? "登录成功": "登录失败");
        //是否是admin角色
        System.out.println(subject.hasRole("admin"));
        //判断是否拥有该权限
        System.out.println(subject.isPermitted("order-del"));
    }
}
```

## demo2

###  代码

config/ShiroConfig:初始化shiro

```java
package com.example.demosec1.config;

import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.HashMap;
import java.util.Map;

@Configuration
//初始化Shiro
public class ShiroConfig {
    @Bean
    //读取ini文件
    public IniRealm getIniRealm(){
        return new IniRealm("classpath:shiro.ini");
    }

    @Bean
    public DefaultWebSecurityManager getDefaultWebSecurityManager(IniRealm iniRealm){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(iniRealm);
        return securityManager;
    }
    //定义ShiroFilter
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(DefaultWebSecurityManager defaultWebSecurityManager){
        ShiroFilterFactoryBean filter = new ShiroFilterFactoryBean();
        filter.setSecurityManager(defaultWebSecurityManager);

        Map<String,String> filterMap = new HashMap<>();

        // 设置拦截器，设置权限
        filterMap.put("/**", "anon");

        filter.setFilterChainDefinitionMap(filterMap);

        // 设置默认登录界面和未验证页面跳转
        filter.setLoginUrl("/login.html");
        filter.setUnauthorizedUrl("/login.html");

        return filter;
    }
}



```

controller/UserController:路由控制器

```java
package com.example.demosec1.controller;

import com.example.demosec1.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    UserService userService;

    @PostMapping("/login")
    public String login(String username,String password){
        try {
            userService.checkLogin(username,password);
            return "login successfully!";
        } catch (Exception e) {
            return "error";
        }
    }
    @PostMapping("/register")
    public String register(String username,String password){

        return "username:"+username+"\t"+"password:"+password;
    }
}


```

sercvice/UserService:处理请求

```java
package com.example.demosec1.service;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    public void checkLogin(String username, String password) throws Exception{
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        subject.login(token);
    }
}


```

resource/static/login.html

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
Login Page
<form action="user/login" method="post">
    账号：<input type="text" name="username">
    密码：<input type="text" name="password">
    <input type="submit" value="登录">
</form>
</body>
</html>

```

