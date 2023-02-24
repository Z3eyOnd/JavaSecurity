##  SSRF

##  一个基本的URL获取实例

```java
package SSRF;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

public class ssrf_1 {
    public static void main(String[] args) throws Exception {
        //获取一个URL对象
        URL url=new URL("http://www.baidu.com");
        //打开与url的一个连接
        URLConnection connection=url.openConnection();
        //设置发送的参数
        connection.setRequestProperty("user-agent","javasec");
        connection.setConnectTimeout(1000);
        connection.setReadTimeout(1000);
        //建立连接
        connection.connect();
        //获取URL响应的内容(网页的内容)
        connection.getInputStream();
        //获取响应头部字段信息列表
        System.out.println(connection.getHeaderField("Server"));
        System.out.println(connection.getHeaderFields().toString());
        StringBuilder response=new StringBuilder();
        BufferedReader in=new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String line=in.readLine();
        while(line!=null){
            response.append("\n").append(line);
            line=in.readLine();
        }
        System.out.println(response.toString());
    }
}

```

##  SSRF的一个例子

SSRF： 由攻击者构造的攻击链接传给服务端执行造成的漏洞，一般用来在外网探测或攻击内网服务。

漏洞形成的原因大部分是因为服务端提供了可以从其他服务器获取资源的功能，然而并没有对用户的输入以及发起请求的url进行过滤&限制，从而导致了ssrf的漏洞。

ssrf常见的位置：

- 抓取用户输入图片的地址并且本地化存储
- 从远程服务器请求资源
- 对外发起网络请求

利用file进行对文件的读取

```java
package SSRF;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

public class ssrf_2 {
    public static void main(String[] args) throws Exception {
        URL url=new URL("file:///D:/java/javasec/Security_jdk8/flag.txt");
        URLConnection connection=url.openConnection();
        connection.setRequestProperty("user-agent","javasec");
        connection.connect();
        StringBuilder response=new StringBuilder();
        BufferedReader in=new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String line=in.readLine();
        while(line!=null){
            response.append('\n').append(line);
            line=in.readLine();
        }
        System.out.println(response.toString());
    }
}

```

`SSRF`漏洞对使用不同类发起的url请求有点区别，如果是`URLConnection|URL`发起的请求，那么对于上文中所提到的所有`protocol`都支持，但是如果经过二次包装或者其他的一些类发出的请求，比如

```
HttpURLConnection
HttpClient
Request
okhttp
```

只支持发起`http|https`协议，否则会抛出异常。

在利用`http`协议时，如果是web服务的端口，会输出网页源码，如果不是，会爆出异常，这样可以探测内网所有服务端口

- 利用file协议读取文件内容（仅限使用`URLConnection|URL`发起的请求）
- 利用http 进行内网web服务端口探测
- 利用http 进行内网非web服务端口探测(如果将异常抛出来的情况下)
- 利用http进行ntlmrelay攻击(仅限`HttpURLConnection`或者二次包装`HttpURLConnection`并未复写`AuthenticationInfo`方法的对象)

##  参考文章

https://www.ddosi.org/attacking-java-rmi-via-ssrf/

https://www.freebuf.com/vuls/293473.html