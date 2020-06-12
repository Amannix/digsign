// sha256.c
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "../../include/ksig/sha256.h"

#define rightrotate(w, n) ((w >> n) | (w) << (32-(n)))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define copy_uint32(p, val) *((__u32 *)p) = __builtin_bswap32((val))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define copy_uint32(p, val) *((__u32 *)p) = (val)
#else
#error "Unsupported target architecture endianess!"
#endif

static const __u32 k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*int ksha256(FILE *thefile, unsigned long offset, unsigned long len, unsigned char *out) {
    unsigned long i,idx;
    int r = (int)(len * 8 % 512);//转为bit
    unsigned long append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;
    size_t new_len = len + append + 8;
    unsigned char *buf = kmalloc(1024*1024, GFP_ATOMIC);
    __u32 h0 = 0x6a09e667;
    __u32 h1 = 0xbb67ae85;
    __u32 h2 = 0x3c6ef372;
    __u32 h3 = 0xa54ff53a;
    __u32 h4 = 0x510e527f;
    __u32 h5 = 0x9b05688c;
    __u32 h6 = 0x1f83d9ab;
    __u32 h7 = 0x5be0cd19;
    __u64 bits_len = len * 8;
    __u32 w[64];
    size_t chunk_len = new_len / 64;
    fseek(thefile, offset, SEEK_SET);
    memset(w, 0, 64);
    unsigned long int sum = 0;
    chunk_len /= 16384;
    for (idx = 0; idx <= chunk_len; idx++) {
        //printk("%x %d %d %d %d",offset, chunk_len, new_len,sum,append);
        fseek(thefile ,offset + sum, SEEK_SET);
        int j = 0,count = 1024*1024/64;
        if (idx == chunk_len){
            int stunk = len - sum;
            //printk("%d %d %d\n",stunk, len, stunk + append);
            if (stunk > 0 && fread(buf, stunk, 1, thefile)){
                memset(buf+stunk, 0, append);
                buf[stunk] = (unsigned char)0x80;
                for (i = 0; i < 8; i++) {
                    buf[stunk + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
                }
                count = (stunk + append + 8)/64;
                if (append != 0){
                    ++count;
                }
            }
        }else{
            //printk("%d %d %d\n",1, len, offset+sum);
            if (fread(buf, 1024*1024, 1, thefile) == 0){
                return FALSE;
            }
        }

        for (j = 0;j < count; ++j){
            __u32 val = 0;
            __u32 a = h0;
            __u32 b = h1;
            __u32 c = h2;
            __u32 d = h3;
            __u32 e = h4;
            __u32 f = h5;
            __u32 g = h6;
            __u32 h = h7;
            for (i = 0; i < 64; i++) {
                val =  val | (*(buf + j * 64 + i) << (8 * (3 - i)));
                if (i % 4 == 3) {
                    w[i / 4] = val;
                    val = 0;
                }
            }
            for (i = 16; i < 64; i++) {
                __u32 s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
                __u32 s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            for (i = 0; i < 64; i++) {
                __u32 s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
                __u32 ch = (e & f) ^ (~e & g);
                __u32 temp1 = h + s_1 + ch + k[i] + w[i];
                __u32 s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
                __u32 maj = (a & b) ^ (a & c) ^ (b & c);
                __u32 temp2 = s_0 + maj;
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }
        sum += 8192;
    }
    copy_uint32(out, h0);
    copy_uint32(out + 1, h1);
    copy_uint32(out + 2, h2);
    copy_uint32(out + 3, h3);
    copy_uint32(out + 4, h4);
    copy_uint32(out + 5, h5);
    copy_uint32(out + 6, h6);
    copy_uint32(out + 7, h7);
    kfree(buf);
}*/

void sha256(const unsigned char *data, size_t len, unsigned char *out) {
    int i,idx;
    int r = (int)(len * 8 % 512);//转为bit
    int append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;
    size_t new_len = len + append + 8;
    unsigned char *buf = kmalloc(new_len, GFP_ATOMIC);
    __u32 h0 = 0x6a09e667;
    __u32 h1 = 0xbb67ae85;
    __u32 h2 = 0x3c6ef372;
    __u32 h3 = 0xa54ff53a;
    __u32 h4 = 0x510e527f;
    __u32 h5 = 0x9b05688c;
    __u32 h6 = 0x1f83d9ab;
    __u32 h7 = 0x5be0cd19;
    __u64 bits_len = len * 8;
    __u32 w[64]; 
    size_t chunk_len = new_len / 64;
    memset(buf+len, 0, append);
    if (len > 0) {
        memcpy(buf, data, len);
    }
    buf[len] = (unsigned char)0x80;
    
    for (i = 0; i < 8; i++) {
        buf[len + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
    }

    memset(w, 0, 64);

    for (idx = 0; idx < chunk_len; idx++) {
        __u32 val = 0;
        __u32 a = h0;
        __u32 b = h1;
        __u32 c = h2;
        __u32 d = h3;
        __u32 e = h4;
        __u32 f = h5;
        __u32 g = h6;
        __u32 h = h7;
        for (i = 0; i < 64; i++) {
            val =  val | (*(buf + idx * 64 + i) << (8 * (3 - i)));
            if (i % 4 == 3) {
                w[i / 4] = val;
                val = 0;
            }
        }
        for (i = 16; i < 64; i++) {
            __u32 s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            __u32 s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        for (i = 0; i < 64; i++) {
            __u32 s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
            __u32 ch = (e & f) ^ (~e & g);
            __u32 temp1 = h + s_1 + ch + k[i] + w[i];
            __u32 s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
            __u32 maj = (a & b) ^ (a & c) ^ (b & c);
            __u32 temp2 = s_0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    copy_uint32(out, h0);
    copy_uint32(out + 1, h1);
    copy_uint32(out + 2, h2);
    copy_uint32(out + 3, h3);
    copy_uint32(out + 4, h4);
    copy_uint32(out + 5, h5);
    copy_uint32(out + 6, h6);
    copy_uint32(out + 7, h7);
    kfree(buf);
}