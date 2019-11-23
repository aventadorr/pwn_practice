First approach is , getting libc leak and then try to overwrite `__malloc_hook`

1) can get libc leak --> when u put huge chunk into malloc like `0x300000`
2) calculate offset for `__malloc_hook`
3) control that function then overwrite `one_gadget`

```
Program received signal SIGSEGV (fault address 0x0)
pwndbg> x/gx __malloc_hook
0x7fd1182052c5 <do_system+1045>:        0x310039e3d4358d48
pwndbg>
```

I was able to control the function but no luck to gain shell

Second approach is ,

1) get libc leak with same method
2) calculate offset for `__realloc_hook` 
3) set __malloc_hook to libc+0x105ae0 and __realloc_hook to second one gadget.(there are some alternative solutions)

then gained shell

flag : `CTF{wh0_kn3w_s3t_c0nt3xt_c0uld_g3t_y0u_sh3ll}`
