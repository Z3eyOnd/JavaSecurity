### 什么是context

> 上下文其实是一个抽象的概念。我们常见的上下文有Servlet中的pageContext，访问JNDI时候用的Context。其实他们真正的作用就是承上启下。比如说pageContext他的上层是WEB容器，下层是你写的那个Servlet类，pageContext作为中间的通道让Servlet 和Web容器进行交互。再比如访问JNDI的Context，他的上层是JNDI服务器（可能是远程的），下层是你的应用程序，他的作用也是建立一个通道让你能访问JNDI服务器，同时也让JNDI服务器接受你的请求，同样起到交互作用。
> 

### Thread.currentThread().getContextClassLoader()

>返回该线程的ClassLoader上下文。线程创建者提供ClassLoader上下文，以便运行在该线程的代码在加载类和资源时使用。如果没有，则默认返回父线程的ClassLoader上下文。原始线程的上下文 ClassLoader 通常设定为用于加载应用程序的类加载器。
>
>首先，如果有安全管理器，并且调用者的类加载器不是 null，也不同于其上下文类加载器正在被请求的线程上下文类加载器的祖先，则通过 RuntimePermission("getClassLoader") 权限调用该安全管理器的 checkPermission 方法，查看是否可以获取上下文 ClassLoader。

### 详解常用类加载器：ContextClassLoader

https://jawhiow.github.io/2019/04/24/java/%E8%AF%A6%E8%A7%A3%E5%B8%B8%E7%94%A8%E7%B1%BB%E5%8A%A0%E8%BD%BD%E5%99%A8%EF%BC%9AContextClassLoader/