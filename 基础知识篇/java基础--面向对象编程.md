##  入门知识

###  基础知识

####  变量

变量分为两种：基本类型的变量和引用类型的变量。

char类型，只能是一个字符，且只能用单引号，不能用双引号，双引号是字符串类型。

常量用final表示，且变量命名为大写字母

var关键字

```
StringBuilder sb = new StringBuilder();
var sb = new StringBuilder();
```

基本数据类型和引用类型

```
基本数据类型：整型，浮点型，布尔型，字符型
引用类型：字符串，数组，对象实例
引用类型的变量，该变量保存了值的地址，当变量值发生变化时，变量其实改变的是变量指向的地址
```

####  运算

`+-*/%`,`+=`等

`++`和`--`等

移位运算：二进制左右移动

与，或，非，异或

强制类型和自动类型转换：大转小和小转大

三元运算符，短路运算

####  字符和字符串

Java在内存中总是使用Unicode表示字符，所以，一个英文字符和一个中文字符都用一个`char`类型表示，它们都占用两个字节。要显示一个字符的Unicode编码，只需将`char`类型直接赋值给`int`类型，还可以直接用转义字符`\u`+Unicode编码来表示一个字符

字符串用双引号，有时候需要用`\`进行转义，利用`+`进行字符串的拼接，`""" ....."""`多行字符串

### 数组操作

Java的数组有几个特点：

- 数组所有元素初始化为默认值，整型都是`0`，浮点型是`0.0`，布尔型是`false`；
- 数组一旦创建后，大小就不可改变。

要访问数组中的某一个元素，需要使用索引。数组索引从`0`开始，例如，5个元素的数组，索引范围是`0`~`4`。 

可以修改数组中的某一个元素，使用赋值语句，例如，`ns[1] = 79;`。



数组大小：ns.length

创建数组

```java
int[] ns = new int[] { 68, 79, 91, 85, 62 };
int[] ns = new int[5];
int ns []={1,2,3}
```

遍历数组

```java
for (int i=0; i<ns.length; i++) {
            System.out.println(ns[i]);
        }
for (int n : ns) {
            System.out.println(n);
        }
标准库:Arrays.toString(ns)
```

数组排序

```java
 for (int i = 0; i < ns.length - 1; i++) {
            for (int j = 0; j < ns.length - i - 1; j++) {
                if (ns[j] > ns[j+1]) {
                    //交换ns[j]和ns[j+1]
                    int tmp = ns[j];
                    ns[j] = ns[j+1];
                    ns[j+1] = tmp;
                }
            }
        }
标准库：Arrays.sort(ns);
```

多维数组

```java
 int[][] ns = {
            { 1, 2, 3, 4 },
            { 5, 6, 7, 8 },
            { 9, 10, 11, 12 }
        };
        System.out.println(ns.length); // 3
```

遍历二维数组

```java
for (int[] arr : ns) {
    for (int n : arr) {
        System.out.print(n);
        System.out.print(', ');
    }
    System.out.println();
}
```

命令行参数

Java程序的入口是`main`方法，而`main`方法可以接受一个命令行参数，它是一个`String[]`数组

```java
public class Main {
    public static void main(String[] args) {
        for (String arg : args) {
            System.out.println(arg);
        }
    }
}
```

###  流程控制

#### 格式化字符串

输出的语句：`System.out.println()`,`println`是print line的缩写，表示输出并换行。因此，如果输出后不想换行，可以用`print()`：

格式化输出：

| 占位符 | 说明                             |
| :----- | :------------------------------- |
| %d     | 格式化输出整数                   |
| %x     | 格式化输出十六进制整数           |
| %f     | 格式化输出浮点数                 |
| %e     | 格式化输出科学计数法表示的浮点数 |
| %s     | 格式化字符串                     |

```java
System.out.printf("%.2f\n", d); // 显示两位小数3.14
System.out.printf("n=%d, hex=%08x", n, n);//n=12345000, hex=00bc5ea8
```

输入：

```java
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in); // 创建Scanner对象
        System.out.print("Input your name: "); // 打印提示
        String name = scanner.nextLine(); // 读取一行输入并获取字符串
        System.out.print("Input your age: "); // 打印提示
        int age = scanner.nextInt(); // 读取一行输入并获取整数
        System.out.printf("Hi, %s, you are %d\n", name, age); // 格式化输出
    }
}
```

####  switch语句

注意有无break



```java
public class Main {
    public static void main(String[] args) {
        String fruit = "apple";
        switch (fruit) {
        case "apple":
            System.out.println("Selected apple");
            break;
        case "pear":
            System.out.println("Selected pear");
            break;
        case "mango":
            System.out.println("Selected mango");
            break;
        default:
            System.out.println("No fruit selected");
            break;
        }
    }
}
```

新语法：可以返回值

```java
public class Main {
    public static void main(String[] args) {
        String fruit = "apple";
        int opt = switch (fruit) {
            case "apple" -> 1;
            case "pear", "mango" -> 2;
            default -> 0;
        }; // 注意赋值语句要以;结束
        System.out.println("opt = " + opt);
    }
}
```

```java
public class Main {
    public static void main(String[] args) {
        String fruit = "orange";
        int opt = switch (fruit) {
            case "apple" -> 1;
            case "pear", "mango" -> 2;
            default -> {
                int code = fruit.hashCode();
                yield code; // switch语句返回值
            }
        };
        System.out.println("opt = " + opt);
    }
}
```

#### 循环

for，while，do{}while语句

还有break和continue语句。

##  面向对象编程

###  方法

1. 在属性，可以利用`public修饰`，就可以直接外部访问，

   但是一般用private去修饰属性，利用`getName`和`setName`可以访问`private修饰`的类的属性。

   ```java
   public class function {
       public static void main(String[] args) {
           Person person = new Person();
           person.setName("xiao ming");
           person.setAge(18);
           System.out.println(person.getName()+"age is"+person.getAge());
       }
   }
   class Person{
       private int age;
       private String name;
       public int getAge(){
           return this.age;
       }
       public void setAge(int age){
           this.age=age;
       }
       public String getName(){
           return this.name;
       }
       public void setName(String name){
           this.name=name;
       }
   }
   ```

   

2. 定义方法

   ```
   修饰符 方法返回类型 方法名(方法参数列表) {
       若干方法语句;
       return 方法返回值;
   }
   ```

3. 利用this变量可以来访问当前实例对象的属性

4. 方法参数（严格要求）和可变参数(...,用于数组传参)

5. 参数绑定，基本数据类型传参就是传值，引用数据类型传值就是传地址。

###  构造方法

方法名是与类名相同,构造方法没有方法返回类型

```java
 private String name;
 private int age;

 public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
```

1.  实例在创建时通过`new`操作符会调用其对应的构造方法，构造方法用于初始化实例；

2. 没有定义构造方法时，编译器会自动创建一个默认的无参数构造方法；

3. 可以定义多个构造方法，编译器根据参数自动判断；

4. 可以在一个构造方法内部调用另一个构造方法，便于代码复用

```java
class Person {
    private String name;
    private int age;

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public Person(String name) {
        this(name, 18); // 调用另一个构造方法Person(String, int)
    }

    public Person() {
        this("Unnamed"); // 调用另一个构造方法Person(String)
    }
}
```

###  方法重载

这种方法名相同，但各自的参数不同，称为方法重载（`Overload`）。

目的是：功能类似的方法使用同一名字，更容易记住，因此，调用起来更简单

注意：方法重载的返回值类型通常都是相同的

```java
class Hello {
    public void hello() {
        System.out.println("Hello, world!");
    }

    public void hello(String name) {
        System.out.println("Hello, " + name + "!");
    }

    public void hello(String name, int age) {
        if (age < 18) {
            System.out.println("Hi, " + name + "!");
        } else {
            System.out.println("Hello, " + name + "!");
        }
    }
}
```

###  继承

关键字为：`extends`

继承是面向对象编程中非常强大的一种机制，它首先可以复用代码。当我们让`Student`从`Person`继承时，`Student`就获得了`Person`的所有功能，我们只需要为`Student`编写新增的功能

```java
class Person {
    private String name;
    private int age;

    public String getName() {...}
    public void setName(String name) {...}
    public int getAge() {...}
    public void setAge(int age) {...}
}

class Student extends Person {
    // 不要重复name和age字段/方法,
    // 只需要定义新增score字段/方法:
    private int score;

    public int getScore() { … }
    public void setScore(int score) { … }
}
```

1. 继承树，任何类，除了`Object`，都会继承自某个类,Object的父类为`null`

2. 父类`protected`修饰的属性，可以被子类访问到。

3. 利用`super`,子类可以调用父类的属性和构造方法。

```java
class Student extends Person {
    protected int score;

    public Student(String name, int age, int score) {
        super(name, age); // 调用父类的构造方法Person(String, int)
        this.score = score;
    }
}
```

4. 阻止继承：从Java 15开始，允许使用`sealed`修饰class，并通过`permits`明确写出能够从该class继承的子类名称

```
public sealed class Shape permits Rect, Circle, Triangle {
    ...
}
```

5. 向上转型和向下转型

```
向上
Person p = new Student(); 

向下
Person p1 = new Student(); // upcasting, ok
Person p2 = new Person();
Student s1 = (Student) p1; // ok
Student s2 = (Student) p2; // runtime error! ClassCastException!
```

为了避免向下转型出错，Java提供了`instanceof`操作符，可以先判断一个实例究竟是不是某种类型

`instanceof`可以检查子类和父类

```
Person p = new Person();
System.out.println(p instanceof Person); // true
System.out.println(p instanceof Student); // false
```

###  多态

1. 覆写（重写）：Override和Overload不同的是，如果方法签名不同，就是Overload，Overload方法是一个新方法；如果方法签名相同，并且返回值也相同，就是`Override`

2. 多态：多态是指，针对某个类型的方法调用，其真正执行的方法取决于运行时期实际类型的方法

3. 覆写Object方法

   因为所有的`class`最终都继承自`Object`，而`Object`定义了几个重要的方法：

   - `toString()`：把instance输出为`String`；
   - `equals()`：判断两个instance是否逻辑相等；
   - `hashCode()`：计算一个instance的哈希值。

### 抽象类

1. 把一个方法声明为`abstract`，表示它是一个抽象方法，本身没有实现任何方法语句，目的就是为了子类去继承他，同时也会强迫子类去覆写方法。因为这个抽象方法本身是无法执行的，所以，`Person`类也无法被实例化。
2. 定义了抽象方法的class必须被定义为抽象类，从抽象类继承的子类必须实现抽象方法；
3. 如果不实现抽象方法，则该子类仍是一个抽象类；
4. 面向抽象编程使得调用者只关心抽象方法的定义，不关心子类的具体实现，上层代码定义规范，下层代码负责实现。

```
class Person {
    public abstract void run();
}
```

###  接口

如果一个抽象类没有字段，所有方法全部都是抽象方法，就可以把该抽象类改写为接口：`interface`。

```
abstract class Person {
    public abstract void run();
    public abstract String getName();
}
```

```
interface Person {
    void run();
    String getName();
}
```

当一个具体的`class`去实现一个`interface`时，需要使用`implements`关键字

在Java中，一个类只能继承自另一个类，不能从多个类继承。但是，一个类可以实现多个`interface`

```
class Student implements Person, Hello { // 实现了两个interface
    ...
}
```

接口继承：一个`interface`可以继承自另一个`interface`。`interface`继承自`interface`使用`extends`，它相当于扩展了接口的方法

![image-20220303200059802](https://z3eyond-top-1304266053.cos.ap-chengdu.myqcloud.com/typora/202203032000897.png)

###  静态字段和静态方法

关键词:`static`

直接利用`类.`来访问，一般不用实例访问

```
Person.number = 99;
System.out.println(Person.number);
```

因为静态方法属于`class`而不属于实例，因此，静态方法内部，无法访问`this`变量，也无法访问实例字段，它只能访问静态字段

### 作用域

关键词：`public`,`protected`,`private`,包作用域，`final`

包作用域是指一个类允许访问同一个`package`的没有`public`、`private`修饰的`class`，以及没有`public`、`protected`、`private`修饰的字段和方法
