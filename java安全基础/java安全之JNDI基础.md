##  JNDI概念

Java命名和目录接口（Java Naming and Directory Interface,JNDI）是一组在Java应用中访问命名和目录服务的API。JNDI中的命名（Naming），就是将Java对象以某个名称的形式绑定（binding）到一个容器环境（Context）中，以后调用容器环境（Context）的查找（lookup）方法又可以查找出某个名称所绑定的Java对象。

命名服务就是将名称和对象进行关联，提供通过名称找到对象的操作，最典型例子就是DNS域名和IP的关联

JNDI可访问的有:JDBC、LDAP、RMI、DNS、NIS、CORBA

##  利用JNDI创建目录服务对象操作

```java
// 创建环境变量对象
Hashtable env = new Hashtable();

// 设置JNDI初始化工厂类名
env.put(Context.INITIAL_CONTEXT_FACTORY, "类名");

// 设置JNDI提供服务的URL地址
env.put(Context.PROVIDER_URL, "url");

// 创建JNDI目录服务对象
DirContext context = new InitialDirContext(env);
```

`Context.INITIAL_CONTEXT_FACTORY(初始上下文工厂的环境属性名称)`指的是`JNDI`服务处理的具体类名称，如：`DNS`服务可以使用`com.sun.jndi.dns.DnsContextFactory`类来处理，`JNDI`上下文工厂类必须实现`javax.naming.spi.InitialContextFactory`接口，通过`重写getInitialContext`方法来创建服务

```java
package javax.naming.spi;

public interface InitialContextFactory {

    public Context getInitialContext(Hashtable<?,?> environment) throws NamingException;

}
```

##  DNS解析

JNDI服务处理的类名称，`com.sun.jndi.dns.DnsContextFactory`

```java
package com.sun.jndi.dns;

public class DnsContextFactory implements InitialContextFactory {

  // 获取处理DNS的JNDI上下文对象
  public Context getInitialContext(Hashtable<?, ?> var1) throws NamingException {
    if (var1 == null) {
      var1 = new Hashtable(5);
    }
    return urlToContext(getInitCtxUrl(var1), var1);
  }
  // 省去其他无关方法和变量
}
```

测试

```java
package JNDI;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
public class DNSTest {
    public static void main(String[] args) {
        //创建一个环境变量对象
        Hashtable env=new Hashtable();
        //设置JNDI初始化工厂类名
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.dns.DnsContextFactory");
        //设置JNDI提供服务的URL地址，可以设置解析的DNS服务器地址
        //可以直接nslookup来查看本地的dns服务器
        env.put(Context.PROVIDER_URL,"dns://61.139.2.69/");
        try {
            // 创建JNDI目录服务对象
            DirContext context = new InitialDirContext(env);

            // 获取DNS解析记录测试
            Attributes attrs1 = context.getAttributes("baidu.com", new String[]{"A"});
            Attributes attrs2 = context.getAttributes("qq.com", new String[]{"A"});

            System.out.println(attrs1);
            System.out.println(attrs2);
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
}

```

## 访问文件系统

maven配置

```xml
<dependency>
    <groupId>com.sun.messaging.mq</groupId>
    <artifactId>fscontext</artifactId>
    <version>4.6-b01</version>
</dependency>
```

首先创建一个环境变量对象，添加内容初始工厂类，引用`com.sun.jndi.fscontext.RefFSContextFactory`类访问文件系统，然后**使用file协议**添加文件系统的初始路径

```java
Hashtable env = new Hashtable();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.fscontext.RefFSContextFactory");
env.put(Context.PROVIDER_URL, "file://C:\\xxx");
Context ctx = new InitialContext(env);
```

列出目录

```java
package JNDI;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import java.util.Hashtable;

public class FileTest {
    public static void main(String[] args) throws Exception {
        Hashtable env=new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.fscontext.RefFSContextFactory");
        env.put(Context.PROVIDER_URL, "file://D:\\wsl\\test1");
        Context ctx = new InitialContext(env);
        NamingEnumeration list =ctx.list(".");
        while(list.hasMore()){
            NameClassPair ncp=(NameClassPair)list.next();
            System.out.println(ncp);
        }
    }
}

```

创建新文件夹

```java
ctx.createSubcontext("testDir");
```

绑定文件：

获取文件的引用

```java
 String file="D:\\java\\javasec\\web\\src\\main\\resources\\test.txt";
 Object obj=ctx.lookup(file);
```

```java
package JNDI;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.io.*;
import java.util.Hashtable;

public class FileTest {
    public static void main(String[] args) throws Exception {
        Hashtable env=new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.fscontext.RefFSContextFactory");
        env.put(Context.PROVIDER_URL, "file://D:\\wsl");
        Context ctx = new InitialContext(env);
        String file="D:\\java\\javasec\\web\\src\\main\\resources\\test.txt";
        Object obj=ctx.lookup(file);
        File f= (File)obj;
        FileInputStream fileInputStream = new FileInputStream(f);
        ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
        int length;
        byte [] data=new byte[32];
        while((length= fileInputStream.read(data))!=-1){
            byteArrayOutputStream.write(data,0,length);
        }
        System.out.println(byteArrayOutputStream);
    }
}

```

##  访问RMI服务

服务端：

```java
package RMI;


import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Server {
    public static void main(String[] args) throws Exception {
        Registry registry= LocateRegistry.createRegistry(1099);
        registry.bind("work",new RMIImpl());
        System.out.println("Server is running!!!");
    }
}

```

客户端：

```java
package RMI;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.rmi.RemoteException;
import java.util.Hashtable;

public class RMITest {
    public static void main(String[] args) throws Exception {
        String providerURL="rmi://127.0.0.1:1099";
        //创建一个环境变量对象
        Hashtable env = new Hashtable();
        //设置JNDI初始化工厂类名
        env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.rmi.registry.RegistryContextFactory");
        //设置JNDI提供服务的URL地址
        env.put(Context.PROVIDER_URL,providerURL);
        //创建一个JNDI目录服务的对象
        try {
            // 创建JNDI目录服务对象
            DirContext context = new InitialDirContext(env);

            // 通过命名服务查找远程RMI绑定的RMITestInterface对象
            RMIInterface testInterface = (RMIInterface) context.lookup("work");

            // 调用远程的RMITestInterface接口的test方法
            testInterface.work();
        } catch (NamingException e) {
            e.printStackTrace();
        } catch (RemoteException e) {
            e.printStackTrace();
        }
    }
}

```

