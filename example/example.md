---
marp: true
theme: XDU
paginate: true
math: katex
---

<!-- backgroundImage: url("../images/bg2.png")
_backgroundImage: url("../images/bg.png")
_paginate: false  -->

<img src="../images/logo.png" alt="logo" style="zoom:14%;" />

<style scoped>
h1 {
  text-align: center;
  margin-top: 70px; /* 大标题上间距 */
  margin-bottom: 70px; /* 大标题下间距 */
  font-size: 114px;
}
</style>

<h1 class="title">example</h1>
<NAME> 田震雄
<DATE> 2023.10

---
<!--_paginate: false  -->

# 1. 目录

<!-- 在此生成目录 -->
- [1. 目录](#1-目录)
- [2. 能实现的效果](#2-能实现的效果)
  - [2.1. 支持markdown语法](#21-支持markdown语法)
- [3. 插入居中的图片](#3-插入居中的图片)
  - [3.1. 文本首字符缩进](#31-文本首字符缩进)
  - [3.2. 生成序号\&\&目录](#32-生成序号目录)
    - [3.2.1. 实时预览\&\&导出](#321-实时预览导出)
- [4. 如果标题实在是太长了有可能会影响目录的观感](#4-如果标题实在是太长了有可能会影响目录的观感)


![bg right:45% ](../images/bg5.jpg)
<!-- TODO:找一张高清图 -->

---

# 2. 能实现的效果
> do something

- 兼容前端语法
- 能自动生成序号目录
- 简易的动画
- ...

---
## 2.1. 支持markdown语法

| A   | B   |
| --- | --- |
| cc  | CC  |
| dd  | DD  |

$$ I_{xx}=\int\int_Ry^2f(x,y)\cdot{}dydx $$

$$
f(x) = \int_{-\infty}^\infty
    \hat f(\xi)\,e^{2 \pi i \xi x}
    \,d\xi
$$

$$
 \begin{vmatrix}
 0&1&2\\
 3&4&5\\
 6&7&8\\
 \end{vmatrix}
 $$

---

- 无动画的列表
  - 用`-`修饰
- 直接全部显示

1. a
   1. aa
2. b
3. c

1) One动态显示
   1) one
2) Two
3) Three

* 有动画的列表
  * 用`*`修饰
* 逐个显示

---

```cpp
//C Code
#include <iostream>
int main(){
  return 0;
}
```
```java
//Java Code
package org.example;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello world!");
    }
}
```

```go
// golang Code
func (c *cpuCollector) updateStat(ch chan<- prometheus.Metric) error {
	stats, err := c.fs.Stat()
	if err != nil {
		return err
	}

	return nil
}
```

---
# 3. 插入居中的图片
定义了`cimg`关键词用于快速添加一个**居中格式**的图片，输入cimg 👉 Tab。

<img src="../images/logo.png" alt="img" style="zoom: 10%;display: block;margin: auto;" />
<img src="../images/logo.png" alt="img" style="zoom: 20%;display: block;margin: auto;" />
<img src="../images/logo.png" alt="img" style="zoom: 30%;display: block;margin: auto;" />

---

# 模版
在md格式的文件中输入init 👉 Tab快速生成模版代码。

---
## 3.1. 文本首字符缩进

无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本无修饰的文本

<SJ>缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本缩进的文本

---
## 3.2. 生成序号&&目录

基于[markdown-all-in-one](https://marketplace.visualstudio.com/items?itemName=yzhang.markdown-all-in-one)
<img src="./CleanShot 2023-10-13 at 16.25.44@2x.png" alt="img" style="zoom: 40%;display: block;margin: auto;" />

---

### 3.2.1. 实时预览&&导出
* 实时预览效果：
  * <img src="CleanShot 2023-10-13 at 16.30.45@2x.png" alt="img" style="zoom: 15%;display: block;margin: auto;" />
   
* 导出为html一定要在md文件相同目录下，否则相对路径的图片会失效
* 导出的html文件有演讲者模式


---
# 4. 如果标题实在是太长了有可能会影响目录的观感
![bg](../images/ending.png)