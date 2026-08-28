void *func_00159768(void *arg0, int arg1, int arg2, int arg3)
{
    void *inner = *(void **)((char *)arg0 + 0x40);
    *(int *)((char *)inner + 0xB0) = arg3;
    *(int *)((char *)inner + 0xA8) = arg1;
    *(int *)((char *)inner + 0xAC) = arg2;
    return inner;
}
