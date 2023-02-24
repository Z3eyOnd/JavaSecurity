##  反序列化

###  demo1

需要反序列化就需要`implements Serialize`接口

```java
package serialize;

import java.io.*;
import java.lang.reflect.Field;

public class TestSerialize {
    public static void main(String[] args) throws Exception {
        File f= File.createTempFile("serialize","out");
        System.out.println("[+]创建对象");
        PersonSerialize p=new PersonSerialize("z3eyond",1);
        System.out.println("[.]序列化");
        ObjectOutputStream oss=new ObjectOutputStream(new FileOutputStream(f));
        oss.writeObject(p);

        System.out.println("[.]反序列化");
        ObjectInputStream ois=new ObjectInputStream(new FileInputStream(f));
        PersonSerialize pp=(PersonSerialize)ois.readObject();
        System.out.println("name is:"+pp.name);
        Class c=pp.getClass();
        Field idd=c.getDeclaredField("id");
        idd.setAccessible(true);
        //idd.set(pp,123);
        System.out.println(pp.toString());
    }
}

class PersonSerialize implements Serializable{
    private static final long serializeVersionUID=-2818606485066001460L;
    public String name;
    private int id;

    public PersonSerialize(){
        System.out.println("无参构造器");
    }
    public PersonSerialize(String name,int id){
        System.out.println("有参构造");
        this.name=name;
        this.id=id;
    }
    public String toString(){
        return "name:"+name+"\n"+
                "id:"+id+"\n";
    }
}
```

###  demo2

`Externalizable`接口

```java
package serialize;
import java.io.*;

class ExternalSerializationTest {
    public static void main(String[] args) throws Exception {

        File f = File.createTempFile("externalserialize",".out");

        System.out.println("[+]创建对象");
        System.out.print("p1 ");
        PersonExternalSerialize p1 = new PersonExternalSerialize();
        System.out.print("p2 ");
        PersonExternalSerialize p2 = new PersonExternalSerialize("zhangsan","Male",12321);

        System.out.println("[.]序列化");
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(f));
        System.out.print("p1 ");
        oos.writeObject(p1);
        System.out.print("p2 ");
        oos.writeObject(p2);

        System.out.println("[.]反序列化");
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f));
        System.out.print("p1 ");
        PersonExternalSerialize pp = (PersonExternalSerialize) ois.readObject();
        System.out.print("p2 ");
        PersonExternalSerialize ppp = (PersonExternalSerialize) ois.readObject();

        System.out.println(pp);
        System.out.println(ppp);

        System.out.println(ppp.sex);

        f.deleteOnExit();
    }
}

class PersonExternalSerialize implements Externalizable{

    private static final long serialVersionUID = 4184813134939827841L;
    public String name;
    public String sex;
    private int id;

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        System.out.println("writeExternal");
        out.writeObject(name);
        out.writeObject(id);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        System.out.println("readExternal");
        this.name = (String) in.readObject();
        this.id = (int) in.readObject();
    }

    public PersonExternalSerialize() {
        System.out.println("无参构造器");
    }

    public PersonExternalSerialize(String name, String sex,int id) {
        System.out.println("有参构造器");
        this.name = name;
        this.sex = sex;
        this.id = id;
    }
}

```

###  区别

- 实现Serializable接口的类**所有属性**都可以被序列化和反序列化；Externalizable接口可以使用方法**指定部分属性被序列化、反序列化**。
- Serializable序列化时不会调用默认构造器；Externalizable会调用默认构造器。