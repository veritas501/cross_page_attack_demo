# Cross Page Attack demo

blog: [https://veritas501.github.io/2023_03_07-Cross Cache Attack技术细节分析](https://veritas501.github.io/2023_03_07-Cross%20Cache%20Attack%E6%8A%80%E6%9C%AF%E7%BB%86%E8%8A%82%E5%88%86%E6%9E%90/)

用linux kernel module的形式演示linux kernel中Cross Page Attack的攻击过程。

关于free page的细节，[这篇文章](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#how-to-free-a-page)教了很多；
这个demo的代码主要来自[这篇文章](https://www.anquanke.com/post/id/285919#h2-2)，我只是小改了一下。

运行：`bash boot.sh`

图中最前面有`[!!]`的那行是在内核中加的，以5.13为例，加在这个位置：
```c
// >>> mm/slub.c:2321
/* 2321 */ static void unfreeze_partials(struct kmem_cache *s,
/* 2322 */ 		struct kmem_cache_cpu *c)
/* 2323 */ {
------
/* 2371 */ 	while (discard_page) {
/* 2372 */ 		page = discard_page;
/* 2373 */ 		discard_page = discard_page->next;
/* 2374 */ 
/* 2375 */ 		stat(s, DEACTIVATE_EMPTY);
			// add debug print here
/* 2376 */ 		pr_err("[!!] call discard_slab, page: %px, page address: %px\n",
/* 2377 */ 				page,page_address(page));
/* 2378 */ 		discard_slab(s, page);
/* 2379 */ 		stat(s, FREE_SLAB);
/* 2380 */ 	}
```

demo模块基于5.13内核编写，其他版本未测试。

![](demo.png)
