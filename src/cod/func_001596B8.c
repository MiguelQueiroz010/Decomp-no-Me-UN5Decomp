int func_001596B8(void *arg0)
{
    void *inner = *(void **)((char *)arg0 + 0x40);
    *(int *)((char *)inner + 0x878) = 1;
    return 1;
}
