int func_0018CCB0(void *arg0, int arg1)
{
    int *value = (int *)((char *)arg0 + 0x58);
    int old = *value;

    *value = arg1;
    return old;
}
