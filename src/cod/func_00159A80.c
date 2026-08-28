int func_00159A80(void *arg0, int arg1)
{
    void *inner = *(void **)((char *)arg0 + 0x40);
    int old = *(int *)((char *)inner + 0xFC);
    *(int *)((char *)inner + 0xFC) = arg1;
    return old;
}
