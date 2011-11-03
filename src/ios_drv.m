#include <CoreFoundation/CFNotificationCenter.h>
#include <UIKit/UIApplication.h>

#include "erl_driver.h"
#include "erl_nif.h"
#include "util.h" //from emonk

/* Driver interface declarations */
int iosdrv_init(void);
ErlDrvData iosdrv_start(ErlDrvPort port, char *command);
int iosdrv_control(ErlDrvData drv_data, unsigned int command, char *buf,
                   int len, char **rbuf, int rlen);

ErlDrvEntry ios_driver_entry = {
    iosdrv_init,
    iosdrv_start,
    NULL,
    NULL,                       /* output */
    NULL,                       /* ready_input */
    NULL,                       /* ready_output */
    "ios_drv",
    NULL,                       /* finish */
    NULL,                       /* handle */
    iosdrv_control,
    NULL,                       /* timeout */
    NULL,                       /* outputv */
    NULL,                       /* ready_async */
    NULL,                       /* flush */
    NULL,                       /* call */
    NULL,                       /* event */
    ERL_DRV_EXTENDED_MARKER,
    ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION,
    ERL_DRV_FLAG_USE_PORT_LOCKING, /* flags */
    NULL,                       /* handle2 */
    NULL                        /* process_exit */
};

static ErlDrvTermData iosdrv_foregrounded = 0;
static ErlDrvTermData iosdrv_process = 0;
static ErlDrvPort iosdrv_port = 0;
static int couchdb_port = 0;

void notificationCallback (CFNotificationCenterRef center,
                           void * observer,
                           CFStringRef name,
                           const void * object,
                           CFDictionaryRef userInfo) {
    NSLog(@"Got request to restart.");
    if(iosdrv_process != 0)
    {
        ErlDrvTermData term[] = {ERL_DRV_ATOM, iosdrv_foregrounded, ERL_DRV_TUPLE, 1};
        driver_send_term(iosdrv_port, iosdrv_process, term, sizeof(term) / sizeof(term[0]));
        iosdrv_process = 0;
    }
}

int iosdrv_init(void)
{
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(), NULL,
            notificationCallback, (CFStringRef) @"CouchDBRequestRestart",
            NULL, CFNotificationSuspensionBehaviorCoalesce);
    return 0;
}

ErlDrvData iosdrv_start(ErlDrvPort port, char *command)
{
    set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
    iosdrv_foregrounded = driver_mk_atom("foregrounded");
    iosdrv_process = driver_connected(port);
    iosdrv_port = port;
    return 0;
}

int iosdrv_control(ErlDrvData drv_data, unsigned int command, char *buf,
              int len, char **rbuf, int rlen)
{
    return -1;
}


ERL_NIF_TERM set_port(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int a;
    if (!enif_get_int(env, argv[0], &a)) {
        return enif_make_badarg(env);
    }
    couchdb_port = a;
    return util_mk_atom(env, "ok");
}

ERL_NIF_TERM get_port(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return enif_make_int(env, couchdb_port);
}

ERL_NIF_TERM post_notification(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary name, key, value;

    ERL_NIF_TERM head, tail, proplist;
    const ERL_NIF_TERM *pair;
    proplist = argv[1];
    unsigned int proplen;
    int pairlen;

    enif_inspect_binary(env, argv[0], &name);
    CFStringRef cfname = CFStringCreateWithBytes(NULL, name.data, name.size, kCFStringEncodingUTF8, false);

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, proplen,
                                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    while(enif_get_list_cell(env, proplist, &head, &tail))
    {
        enif_get_tuple(env, head, &pairlen, &pair);
        enif_inspect_binary(env, pair[0], &key);
        enif_inspect_binary(env, pair[1], &value);
        CFStringRef ck = CFStringCreateWithBytes(NULL, key.data, key.size, kCFStringEncodingUTF8, false);
        CFStringRef cv = CFStringCreateWithBytes(NULL, value.data, value.size, kCFStringEncodingUTF8, false);
        CFDictionaryAddValue(dict, ck, cv);
        CFRelease(ck);
        CFRelease(cv);
        proplist = tail;
    }

    CFNotificationCenterPostNotification(CFNotificationCenterGetLocalCenter(), cfname, NULL, dict, true);
    CFRelease(cfname);
    CFRelease(dict);
    return util_mk_atom(env, "ok");
}

//We're also a NIF for preserving the port number across the VM restart
static ErlNifFunc ios_nif_funcs[] =
{
    {"set_port", 1, set_port},
    {"get_port", 0, get_port},
    {"post_notification", 2, post_notification}
};

ERL_NIF_INIT(couch_ios, ios_nif_funcs, NULL, NULL, NULL, NULL);
