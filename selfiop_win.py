# -*- coding: utf-8 -*-

__author__ = 'Takashi Yahata (@paoneJP)'
__copyright__ = 'Copyright (c) 2014, Takashi Yahata'
__license__ = 'MIT License'


import sys
import os
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer

import win32service
import win32serviceutil
import win32event


SERVICE_NAME = 'SelfIop'
SERVICE_DISPLAY_NAME = 'SelfIop Service'
SERVICE_DESCRIPTION = 'OpenID Connect Self-issued OP Service by @paoneJP'


# --- fix up running environment for Windows Service

if not sys.stdout:
    sys.stdout = open(os.devnull, 'w')
if not sys.stderr:
    sys.stderr = open(os.devnull, 'w')

if os.path.basename(sys.argv[0]).lower() == 'pythonservice.exe':
    import winreg
    k = 'System\\CurrentControlSet\\Services\\' + SERVICE_NAME + \
        '\\PythonClass'
    p = winreg.QueryValue(winreg.HKEY_LOCAL_MACHINE, k)
    os.chdir(os.path.dirname(p))
else:
    dir = os.path.dirname(sys.argv[0])
    if dir:
        os.chdir(dir)

# --- end of fixup


import config
from selfiopd import run

service_stop_event = win32event.CreateEvent(None, 0, 0, None)


class XWSGIServer(ThreadingMixIn, WSGIServer):

    def service_actions(self):
        super().service_actions()

        r = win32event.WaitForSingleObject(service_stop_event, 0)
        if r == win32event.WAIT_OBJECT_0:
             self._BaseServer__shutdown_request = True


class Service(win32serviceutil.ServiceFramework):

    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def SvcDoRun(self):
        run(server_class=XWSGIServer)
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(service_stop_event)


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(Service)
