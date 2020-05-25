#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <asm/uaccess.h>

#include "../include/kstdio.h"

int ferr(char *s)
{
    printk("%s", s);
    return FALSE;
}

int err(char *s)
{
    printk("%s", s);
    return FALSE;
}

void pdbug (unsigned char *buf,int len)
{
    int i;
    char printf[200*4] = {0};
    len = 200 < len ? 200 : len;
    for (i = 0;i < len; ++i){
        sprintf(printf+(3*i), "%02x ", buf[i]);
    }
    printk ("%s", printf);
}


FILE *fopen(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return (FILE *)filp;
}

void fclose(FILE *file) 
{
    filp_close((struct file*)file, NULL);
}

int fread(void *buf, unsigned int size, unsigned int count, FILE *fp)
{
    mm_segment_t oldfs;
    int ret = 0;
    int i = 0;
    unsigned char *data = buf;
    struct file *file = (struct file*) fp;
    

    oldfs = get_fs();
    set_fs(get_ds());
    for (i = 0; i < count; i++)
    {
        int t = vfs_read(file, data, size, &file->f_pos);
        data += size;
        if (t == size){
            ++ret;
        }
    }

    set_fs(oldfs);
    return ret;
}

/*int fwrite(void *buf, unsigned int size, unsigned int count, FILE *fp)
{
    mm_segment_t oldfs;
    int ret = 0;
    int i = 0;
    unsigned char *data = buf;
    struct file *file = (struct file*) fp;

    oldfs = get_fs();
    set_fs(get_ds());
    for (i = 0;i < count; ++i){
        int t = vfs_write(file, data, size, &file->f_pos);
        data += size;
        if (t == size){
            ++ret;
        }
    }

    set_fs(oldfs);
    return ret;
}*/

int fseek(FILE *stream, long offset, int fromwhere)
{
    struct file *fp = stream;
    switch (fromwhere)
    {
    case SEEK_SET:
        fp->f_pos = offset;
        break;
    
    default:
        break;
    }
    return 0;
}