void func_001999C0(void *arg0, int *arg1)
{
    *(short *)((char *)arg0 + 0x8E) = 0xD00;
    *(int *)((char *)arg0 + 0x90) = *arg1;
    *(int *)((char *)arg0 + 0x80) = 0;
}
