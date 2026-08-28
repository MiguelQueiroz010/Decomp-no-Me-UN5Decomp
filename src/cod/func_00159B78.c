void func_00159B78(void *arg0, int arg1, int arg2)
{
    *(int *)((char *)arg0 + 0xC) = arg1;
    *(int *)((char *)arg0 + 4) = arg2;
    *(int *)arg0 = arg1;
    *(int *)((char *)arg0 + 8) = arg1;
}
