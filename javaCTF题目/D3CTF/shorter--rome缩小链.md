## shorter

考点就是Rome链的缩小

先介绍下下Spring Boot打包的两个文件夹内容：META-INF，BOOT-INF，org

### SpringBoot

#### META-INF

META-INF文件夹是MANIFEST.MF文件的宿主。该文件包含有关JAR内容的元数据。例如，存在一个名为Main-Class的条目，该条目使用可执行的JAR文件的静态`main()`指定Java类的名称。

#### BOOT-INF

Spring Boot应用程序从Boot-INF文件夹加载。

应用程序类应放在嵌套的BOOT-INF/classes目录中。依赖关系应放在嵌套的BOOT-INF/lib目录中。

#### org

这个文件夹下主要就是放的SpringBoot的启动类

