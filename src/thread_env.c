#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "thread_env.h"

#define MAX_ENV_COUNT 16
#define ENV_KEY_SIZE  32
#define ENV_VAL_SIZE  64

static pthread_once_t g_key_once;
static pthread_key_t  g_key;

typedef struct {
    char key[ENV_KEY_SIZE];
    char val[ENV_VAL_SIZE];
} thread_env_t;

static void free_thread_env(void *data)
{
    thread_env_t **envs = (thread_env_t **)data;
    thread_env_t *e;
    int i;

    for (i = 0; i < MAX_ENV_COUNT; i++)
    {
        e = *(envs + i);
        if (e)
            free(e);
    }
    free(envs);
}

static void init_thread_key()
{
    pthread_key_create(&g_key, free_thread_env);
}

int set_thread_env(const char *key, const char *val)
{
    thread_env_t **envs = NULL;
    int i = 0;

    if (!key || !val)
        return -1;

    pthread_once(&g_key_once, init_thread_key);
    envs = pthread_getspecific(g_key);
    if (!envs)
    {
        envs = malloc(sizeof(void *) * MAX_ENV_COUNT);
        if (!envs)
        {
            return -1;
        }
        memset(envs, 0, sizeof(void *) * MAX_ENV_COUNT);
        pthread_setspecific(g_key, envs);
    }

    i = 0;
    while (i < MAX_ENV_COUNT && envs[i] && strcmp(key, envs[i]->key))
        i++;
    if (MAX_ENV_COUNT == i)
        return -1;

    if (!envs[i])
    {
        envs[i] = (thread_env_t *)malloc(sizeof(thread_env_t));
        if (!envs[i])
        {
            return -1;
        }
    }
    if (snprintf(envs[i]->key, sizeof(envs[i]->key), "%s", key) < 0)
        return -1;
    if (snprintf(envs[i]->val, sizeof(envs[i]->val), "%s", val) < 0)
        return -1;

    return 0;
}

void clear_thread_env()
{
    thread_env_t **envs = NULL;
    int i;

    pthread_once(&g_key_once, init_thread_key);
    envs = pthread_getspecific(g_key);
    if (!envs)
    {
        return;
    }

    for (i = 0; i < MAX_ENV_COUNT && envs[i]; i++)
    {
        *(envs[i]->val) = '\0';
    }
}

const char *get_thread_env(const char *key)
{
    thread_env_t **envs = NULL;
    int i;

    pthread_once(&g_key_once, init_thread_key);
    envs = pthread_getspecific(g_key);
    if (!envs)
    {
        return NULL;
    }

    for (i = 0; i < MAX_ENV_COUNT && envs[i]; i++)
    {
        if (!strcmp(envs[i]->key, key))
        {
            return envs[i]->val;
        }
    }

    return NULL;
}
