float func_0018B740(void *arg0, float arg1)
{
    float *value = (float *)((char *)arg0 + 0x40);
    float old = *value;

    *value = arg1;
    return old;
}
