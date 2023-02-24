## 字符串和编码

**定义字符串**(引用类型):

```java
String s1 = "Hello!";
//传入一个char数组
String s2 = new String(new char[] {'H', 'e', 'l', 'l', 'o', '!'});
```

**字符串比较**

用`equals`比较

```java
String s1 = "hello";
String s2 = "HELLO".toLowerCase();
System.out.println(s1 == s2);
System.out.println(s1.equals(s2));
```

要忽略大小写比较，使用`equalsIgnoreCase()`方法。

**常用的方法**

```java
// 是否包含子串:
"Hello".contains("ll"); 
//第一个字符匹配的索引
"Hello".indexOf("l"); 
//最后一个
"Hello".lastIndexOf("l"); 
//开始的匹配
"Hello".startsWith("He"); // true
"Hello".endsWith("lo"); // true
```

提取字符串

```
"Hello".substring(2); // "llo"
"Hello".substring(2, 4); "ll"
```

使用trim()方法可以移除字符串首尾空白字符。空白字符包括空格，\t，\r，\n

```
"  \tHello\r\n ".trim(); // "Hello"
```

`strip()`方法也可以移除字符串首尾空白字符，类似中文的空格字符`\u3000`也会被移除。

`isEmpty()`和`isBlank()`来判断字符串是否为空和空白字符串

**替换子串**

要在字符串中替换子串，有两种方法。一种是根据字符或字符串替换：

```
String s = "hello";
s.replace('l', 'w'); // "hewwo"，所有字符'l'被替换为'w'
s.replace("ll", "~~"); // "he~~o"，所有子串"ll"被替换为"~~"
```

另一种是通过正则表达式替换：

```
String s = "A,,B;C ,D";
s.replaceAll("[\\,\\;\\s]+", ","); // "A,B,C,D"
```

上面的代码通过正则表达式，把匹配的子串统一替换为`","`。

**分割字符串**

要分割字符串，使用`split()`方法，并且传入的也是正则表达式：

```
String s = "A,B,C,D";
String[] ss = s.split("\\,"); // {"A", "B", "C", "D"}
```

**拼接字符串**

拼接字符串使用静态方法`join()`，它用指定的字符串连接字符串数组：

```
String[] arr = {"A", "B", "C"};
String s = String.join("***", arr); // "A***B***C"
```

**格式化字符串**

字符串提供了`formatted()`方法和`format()`静态方法，可以传入其他参数，替换占位符，然后生成新的字符串：

```java
public class Main {
    public static void main(String[] args) {
        String s = "Hi %s, your score is %d!";
        System.out.println(s.formatted("Alice", 80));
        System.out.println(String.format("Hi %s, your score is %.2f!", "Bob", 59.5));
    }
}
```

 Run

有几个占位符，后面就传入几个参数。参数类型要和占位符一致。我们经常用这个方法来格式化信息。常用的占位符有：

- `%s`：显示字符串；
- `%d`：显示整数；
- `%x`：显示十六进制整数；
- `%f`：显示浮点数。

**类型转换**

```
//valueOf，转换为string类型
String.valueOf(123); // "123"
//string类型转换位Int类型
int n1 = Integer.parseInt("123"); // 123
```

**字符编码转换**

```java
//string->byte[]
byte[] b2 = "Hello".getBytes("UTF-8"); // 按UTF-8编码转换
//byte[]—>string
byte[] b = ...
String s1 = new String(b, "GBK"); // 按GBK转换
```

##  StringBuilder

它是一个可变对象，可以预分配缓冲区，这样，往`StringBuilder`中新增字符时，不会创建新的临时对象

字符串拼接链式操作

```java
public class Main {
    public static void main(String[] args) {
        var sb = new StringBuilder(1024);
        sb.append("Mr ")
          .append("Bob")
          .append("!")
          .insert(0, "Hello, ");
        System.out.println(sb.toString());
    }
}
```

##  StringJoiner

```java
public class Main {
    public static void main(String[] args) {
        String[] names = {"Bob", "Alice", "Grace"};
        var sj = new StringJoiner(", ", "Hello ", "!");
        for (String name : names) {
            sj.add(name);
        }
        System.out.println(sj.toString());
    }
}
```
