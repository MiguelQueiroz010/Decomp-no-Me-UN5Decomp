int func_00159A30(void *arg0, int arg1)
{
    void *inner = *(void **)((char *)arg0 + 0x40);
    *(int *)((char *)inner + 0xEC) = arg1;
    return 1;
}
